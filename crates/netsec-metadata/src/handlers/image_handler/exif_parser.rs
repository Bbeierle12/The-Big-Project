//! EXIF, IPTC, and XMP metadata parsing utilities.
//!
//! Ported from MetaExtract `handlers/image/exif_parser.rs`.

use crate::types::{
    CameraInfo, CameraSettings, ExifData, ExifDatetime, GpsInfo, IptcData, XmpData,
};
use crate::{MetadataError, MetadataResult};
use chrono::{NaiveDateTime, TimeZone, Utc};
use exif::{In, Reader, Tag, Value};
use quick_xml::events::Event;
use quick_xml::Reader as XmlReader;
use std::collections::HashMap;
use std::io::Cursor;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// EXIF extraction
// ---------------------------------------------------------------------------

/// Extract EXIF data from image bytes.
pub fn extract_exif(data: &[u8]) -> MetadataResult<ExifData> {
    let mut cursor = Cursor::new(data);
    let exif_reader = Reader::new()
        .read_from_container(&mut cursor)
        .map_err(|e| MetadataError::Exif(e.to_string()))?;

    let mut exif = ExifData::default();

    // Camera info.
    let make = get_string_field(&exif_reader, Tag::Make);
    let model = get_string_field(&exif_reader, Tag::Model);
    let lens = get_string_field(&exif_reader, Tag::LensModel);

    if make.is_some() || model.is_some() || lens.is_some() {
        debug!("Found camera info: {:?} {:?}", make, model);
        exif.camera = Some(CameraInfo { make, model, lens });
    }

    // Camera settings.
    let focal_length = get_rational_field(&exif_reader, Tag::FocalLength);
    let aperture = get_rational_field(&exif_reader, Tag::FNumber);
    let iso = get_u32_field(&exif_reader, Tag::PhotographicSensitivity);
    let exposure_time = get_rational_field(&exif_reader, Tag::ExposureTime);

    let shutter_speed = exposure_time.map(|et| {
        if et < 1.0 {
            format!("1/{}", (1.0 / et).round() as u32)
        } else {
            format!("{}s", et)
        }
    });

    let flash = get_u32_field(&exif_reader, Tag::Flash).map(|f| (f & 1) == 1);
    let exposure_mode =
        get_u32_field(&exif_reader, Tag::ExposureProgram).map(exposure_program_str);
    let metering_mode = get_u32_field(&exif_reader, Tag::MeteringMode).map(metering_mode_str);
    let white_balance = get_u32_field(&exif_reader, Tag::WhiteBalance).map(white_balance_str);

    if focal_length.is_some()
        || aperture.is_some()
        || iso.is_some()
        || shutter_speed.is_some()
        || flash.is_some()
    {
        exif.settings = Some(CameraSettings {
            focal_length,
            aperture,
            shutter_speed,
            iso,
            flash,
            exposure_mode,
            metering_mode,
            white_balance,
        });
    }

    // Datetime.
    let original = parse_exif_date(&get_string_field(&exif_reader, Tag::DateTimeOriginal));
    let digitized = parse_exif_date(&get_string_field(&exif_reader, Tag::DateTimeDigitized));
    let modified = parse_exif_date(&get_string_field(&exif_reader, Tag::DateTime));

    if original.is_some() || digitized.is_some() || modified.is_some() {
        exif.datetime = Some(ExifDatetime {
            original,
            digitized,
            modified,
        });
    }

    // GPS.
    let latitude = extract_gps_coordinate(&exif_reader, Tag::GPSLatitude, Tag::GPSLatitudeRef);
    let longitude =
        extract_gps_coordinate(&exif_reader, Tag::GPSLongitude, Tag::GPSLongitudeRef);
    let altitude = get_rational_field(&exif_reader, Tag::GPSAltitude);

    if latitude.is_some() || longitude.is_some() || altitude.is_some() {
        debug!("Found GPS: lat={:?}, lon={:?}", latitude, longitude);
        exif.gps = Some(GpsInfo {
            latitude,
            longitude,
            altitude,
            timestamp: None,
        });
    }

    // Other fields.
    exif.software = get_string_field(&exif_reader, Tag::Software);
    exif.orientation = get_u16_field(&exif_reader, Tag::Orientation);

    Ok(exif)
}

// ---------------------------------------------------------------------------
// IPTC extraction
// ---------------------------------------------------------------------------

/// Extract IPTC data from JPEG image bytes.
pub fn extract_iptc(data: &[u8]) -> Option<IptcData> {
    let iptc_data = find_iptc_segment(data)?;
    parse_iptc_records(&iptc_data)
}

/// Find IPTC segment in JPEG data.
fn find_iptc_segment(data: &[u8]) -> Option<Vec<u8>> {
    // JPEG must start with SOI marker.
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }

    let mut offset = 2;
    while offset < data.len() - 4 {
        if data[offset] != 0xFF {
            offset += 1;
            continue;
        }

        let marker = data[offset + 1];

        // APP13 marker (0xED) contains IPTC data.
        if marker == 0xED {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            if offset + 2 + length > data.len() {
                return None;
            }

            let segment = &data[offset + 4..offset + 2 + length];

            // Look for "Photoshop 3.0" identifier.
            if segment.starts_with(b"Photoshop 3.0") {
                return find_8bim_iptc(segment);
            }
        }

        // Skip to next marker.
        if (0xE0..=0xEF).contains(&marker) {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 2 + length;
        } else if marker == 0xD9 || marker == 0xDA {
            break;
        } else {
            offset += 1;
        }
    }

    None
}

/// Find IPTC data within Photoshop 8BIM resources.
fn find_8bim_iptc(segment: &[u8]) -> Option<Vec<u8>> {
    // Skip "Photoshop 3.0\0" header (14 bytes).
    let mut offset = 14;

    while offset < segment.len() - 12 {
        // Look for 8BIM signature.
        if &segment[offset..offset + 4] != b"8BIM" {
            offset += 1;
            continue;
        }

        let resource_id = u16::from_be_bytes([segment[offset + 4], segment[offset + 5]]);

        // Skip pascal string (name).
        let name_len = segment[offset + 6] as usize;
        let name_padding = if name_len.is_multiple_of(2) { 1 } else { 0 };
        let data_offset = offset + 7 + name_len + name_padding;

        if data_offset + 4 > segment.len() {
            break;
        }

        let data_len = u32::from_be_bytes([
            segment[data_offset],
            segment[data_offset + 1],
            segment[data_offset + 2],
            segment[data_offset + 3],
        ]) as usize;

        // Resource ID 0x0404 is IPTC-NAA record.
        if resource_id == 0x0404 {
            let iptc_start = data_offset + 4;
            let iptc_end = iptc_start + data_len;
            if iptc_end <= segment.len() {
                return Some(segment[iptc_start..iptc_end].to_vec());
            }
        }

        // Move to next resource (padded to even boundary).
        let padding = if data_len % 2 == 1 { 1 } else { 0 };
        offset = data_offset + 4 + data_len + padding;
    }

    None
}

/// Parse IPTC-IIM records.
fn parse_iptc_records(data: &[u8]) -> Option<IptcData> {
    let mut iptc = IptcData::default();
    let mut keywords = Vec::new();
    let mut offset = 0;

    while offset < data.len() - 5 {
        // IPTC record marker.
        if data[offset] != 0x1C {
            offset += 1;
            continue;
        }

        let record = data[offset + 1];
        let dataset = data[offset + 2];
        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]) as usize;

        if offset + 5 + length > data.len() {
            break;
        }

        let value = &data[offset + 5..offset + 5 + length];
        let value_str = String::from_utf8_lossy(value).trim().to_string();

        // Record 2 is the Application Record (most common metadata).
        if record == 2 {
            match dataset {
                5 => iptc.title = Some(value_str),
                25 => keywords.push(value_str),
                55 => {
                    if let Some(date) = parse_iptc_date(&value_str) {
                        iptc.date_created = Some(date);
                    }
                }
                80 => iptc.creator = Some(value_str),
                90 => iptc.city = Some(value_str),
                101 => iptc.country = Some(value_str),
                110 => iptc.credit = Some(value_str),
                115 => iptc.source = Some(value_str),
                116 => iptc.copyright = Some(value_str),
                120 => iptc.description = Some(value_str),
                _ => {}
            }
        }

        offset += 5 + length;
    }

    if !keywords.is_empty() {
        iptc.keywords = Some(keywords);
    }

    // Return None if no fields were populated.
    if iptc.title.is_none()
        && iptc.description.is_none()
        && iptc.keywords.is_none()
        && iptc.creator.is_none()
        && iptc.copyright.is_none()
    {
        return None;
    }

    debug!("Extracted IPTC data: title={:?}", iptc.title);
    Some(iptc)
}

/// Parse IPTC date string (YYYYMMDD format).
fn parse_iptc_date(date_str: &str) -> Option<chrono::DateTime<Utc>> {
    if date_str.len() != 8 {
        return None;
    }

    let year: i32 = date_str[0..4].parse().ok()?;
    let month: u32 = date_str[4..6].parse().ok()?;
    let day: u32 = date_str[6..8].parse().ok()?;

    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

// ---------------------------------------------------------------------------
// XMP extraction
// ---------------------------------------------------------------------------

/// Extract XMP data from image bytes using proper XML parsing.
pub fn extract_xmp(data: &[u8]) -> Option<XmpData> {
    let xmp_bytes = find_xmp_packet(data)?;
    let xmp_str = String::from_utf8_lossy(&xmp_bytes);

    debug!("Found XMP packet, {} bytes", xmp_bytes.len());

    parse_xmp_xml(&xmp_str)
}

/// Find XMP packet in image data.
fn find_xmp_packet(data: &[u8]) -> Option<Vec<u8>> {
    let start_marker = b"<?xpacket begin";
    let end_marker = b"<?xpacket end";

    let start = find_subsequence(data, start_marker)?;

    let xml_start = find_subsequence(&data[start..], b"<x:xmpmeta")
        .or_else(|| find_subsequence(&data[start..], b"<rdf:RDF"))?;

    let search_start = start + xml_start;
    let end = find_subsequence(&data[search_start..], end_marker)?;

    Some(data[search_start..search_start + end].to_vec())
}

/// Parse XMP XML using quick-xml.
fn parse_xmp_xml(xml: &str) -> Option<XmpData> {
    let mut xmp = XmpData::default();
    let mut reader = XmlReader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut current_element = String::new();
    let mut in_description = false;
    let mut in_bag_or_seq = false;
    let mut collecting_list: Option<String> = None;
    let mut list_items: Vec<String> = Vec::new();
    let mut raw_values: HashMap<String, serde_json::Value> = HashMap::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local_name = name.split(':').next_back().unwrap_or(&name);

                if local_name == "Description" {
                    in_description = true;

                    for attr in e.attributes().flatten() {
                        let key =
                            String::from_utf8_lossy(attr.key.as_ref()).to_string();
                        let value =
                            String::from_utf8_lossy(&attr.value).to_string();

                        match key.as_str() {
                            "xmp:Rating" => {
                                if let Ok(r) = value.parse::<u8>() {
                                    xmp.rating = Some(r);
                                }
                            }
                            "xmp:Label" => xmp.label = Some(value.clone()),
                            "dc:creator" => xmp.creator = Some(vec![value.clone()]),
                            "dc:title" => xmp.title = Some(value.clone()),
                            "dc:description" => {
                                xmp.description = Some(value.clone());
                            }
                            "dc:rights" => xmp.rights = Some(value.clone()),
                            _ => {
                                raw_values.insert(
                                    key,
                                    serde_json::Value::String(value),
                                );
                            }
                        }
                    }
                } else if in_description {
                    current_element = local_name.to_string();

                    if local_name == "Bag"
                        || local_name == "Seq"
                        || local_name == "Alt"
                    {
                        in_bag_or_seq = true;
                    } else if local_name == "li" && in_bag_or_seq {
                        // Will collect text content.
                    } else if !in_bag_or_seq
                        && matches!(
                            current_element.as_str(),
                            "creator"
                                | "subject"
                                | "title"
                                | "description"
                                | "rights"
                        )
                    {
                        collecting_list = Some(current_element.clone());
                        list_items.clear();
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                if in_description && !current_element.is_empty() {
                    let text = e.unescape().ok()?.trim().to_string();
                    if !text.is_empty() {
                        if in_bag_or_seq {
                            list_items.push(text);
                        } else {
                            match current_element.as_str() {
                                "Rating" => {
                                    if let Ok(r) = text.parse::<u8>() {
                                        xmp.rating = Some(r);
                                    }
                                }
                                "Label" => xmp.label = Some(text),
                                "title" => xmp.title = Some(text),
                                "description" => xmp.description = Some(text),
                                "rights" => xmp.rights = Some(text),
                                _ => {
                                    raw_values.insert(
                                        current_element.clone(),
                                        serde_json::Value::String(text),
                                    );
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let name =
                    String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local_name = name.split(':').next_back().unwrap_or(&name);

                if local_name == "Description" {
                    in_description = false;
                } else if local_name == "Bag"
                    || local_name == "Seq"
                    || local_name == "Alt"
                {
                    in_bag_or_seq = false;

                    if let Some(ref field) = collecting_list {
                        if !list_items.is_empty() {
                            match field.as_str() {
                                "creator" => {
                                    xmp.creator = Some(list_items.clone());
                                }
                                "subject" => {
                                    xmp.subject = Some(list_items.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    collecting_list = None;
                    list_items.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                warn!("XMP parsing error: {}", e);
                break;
            }
            _ => {}
        }
        buf.clear();
    }

    if !raw_values.is_empty() {
        xmp.raw = Some(raw_values);
    }

    // Return None if no meaningful data was extracted.
    if xmp.rating.is_none()
        && xmp.label.is_none()
        && xmp.title.is_none()
        && xmp.description.is_none()
        && xmp.creator.is_none()
        && xmp.subject.is_none()
        && xmp.rights.is_none()
        && xmp.raw.is_none()
    {
        return None;
    }

    Some(xmp)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Get string field from EXIF.
fn get_string_field(reader: &exif::Exif, tag: Tag) -> Option<String> {
    reader.get_field(tag, In::PRIMARY).and_then(|f| {
        if let Value::Ascii(ref v) = f.value {
            v.first()
                .map(|s| String::from_utf8_lossy(s).trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            Some(f.display_value().to_string())
                .filter(|s| !s.is_empty() && s != "\"\"")
        }
    })
}

/// Get rational field as f64.
fn get_rational_field(reader: &exif::Exif, tag: Tag) -> Option<f64> {
    reader.get_field(tag, In::PRIMARY).and_then(|f| {
        if let Value::Rational(ref v) = f.value {
            v.first().map(|r| r.num as f64 / r.denom as f64)
        } else {
            None
        }
    })
}

/// Get unsigned integer field.
fn get_u32_field(reader: &exif::Exif, tag: Tag) -> Option<u32> {
    reader
        .get_field(tag, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Short(v) => v.first().map(|&x| x as u32),
            Value::Long(v) => v.first().copied(),
            _ => None,
        })
}

/// Get u16 field.
fn get_u16_field(reader: &exif::Exif, tag: Tag) -> Option<u16> {
    reader.get_field(tag, In::PRIMARY).and_then(|f| {
        if let Value::Short(ref v) = f.value {
            v.first().copied()
        } else {
            None
        }
    })
}

/// Parse EXIF date string to DateTime.
fn parse_exif_date(date_str: &Option<String>) -> Option<chrono::DateTime<Utc>> {
    let s = date_str.as_ref()?;
    // EXIF format: "YYYY:MM:DD HH:MM:SS"
    NaiveDateTime::parse_from_str(s, "%Y:%m:%d %H:%M:%S")
        .ok()
        .map(|dt| Utc.from_utc_datetime(&dt))
}

/// Extract GPS coordinate from EXIF.
fn extract_gps_coordinate(
    reader: &exif::Exif,
    coord_tag: Tag,
    ref_tag: Tag,
) -> Option<f64> {
    let coord_field = reader.get_field(coord_tag, In::PRIMARY)?;
    let ref_field = reader.get_field(ref_tag, In::PRIMARY)?;

    let (degrees, minutes, seconds) = if let Value::Rational(ref v) = coord_field.value {
        if v.len() >= 3 {
            (
                v[0].num as f64 / v[0].denom as f64,
                v[1].num as f64 / v[1].denom as f64,
                v[2].num as f64 / v[2].denom as f64,
            )
        } else {
            return None;
        }
    } else {
        return None;
    };

    let mut decimal = degrees + minutes / 60.0 + seconds / 3600.0;

    // Check reference (N/S for latitude, E/W for longitude).
    if let Value::Ascii(ref v) = ref_field.value {
        if let Some(ref_val) = v.first() {
            if !ref_val.is_empty() && (ref_val[0] == b'S' || ref_val[0] == b'W') {
                decimal = -decimal;
            }
        }
    }

    Some(decimal)
}

/// Find subsequence in byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Convert exposure program value to string.
fn exposure_program_str(value: u32) -> String {
    match value {
        0 => "Not defined".to_string(),
        1 => "Manual".to_string(),
        2 => "Program AE".to_string(),
        3 => "Aperture priority".to_string(),
        4 => "Shutter priority".to_string(),
        5 => "Creative".to_string(),
        6 => "Action".to_string(),
        7 => "Portrait".to_string(),
        8 => "Landscape".to_string(),
        _ => format!("Unknown ({})", value),
    }
}

/// Convert metering mode value to string.
fn metering_mode_str(value: u32) -> String {
    match value {
        0 => "Unknown".to_string(),
        1 => "Average".to_string(),
        2 => "Center-weighted".to_string(),
        3 => "Spot".to_string(),
        4 => "Multi-spot".to_string(),
        5 => "Multi-segment".to_string(),
        6 => "Partial".to_string(),
        255 => "Other".to_string(),
        _ => format!("Unknown ({})", value),
    }
}

/// Convert white balance value to string.
fn white_balance_str(value: u32) -> String {
    match value {
        0 => "Auto".to_string(),
        1 => "Manual".to_string(),
        _ => format!("Unknown ({})", value),
    }
}
