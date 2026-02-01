/**
 * Vite Configuration for Building the NetworkCanvas Widget
 *
 * This config builds a standalone IIFE bundle of the React NetworkCanvas
 * widget for embedding in the Rust Iced desktop application via Wry webview.
 *
 * The output is placed in crates/netsec-gui/assets/webview/ for the Rust
 * build to include.
 */

import path from 'path';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],

  // Build as a self-contained bundle
  build: {
    // Output to Rust crate's assets directory
    outDir: path.resolve(__dirname, '../crates/netsec-gui/assets/webview'),
    emptyOutDir: false, // Don't delete index.html

    // Build as IIFE for embedding in webview
    lib: {
      entry: path.resolve(__dirname, 'widget/index.tsx'),
      name: 'NetworkCanvasWidget',
      formats: ['iife'],
      fileName: () => 'widget.js',
    },

    // Inline everything for a single-file bundle
    rollupOptions: {
      output: {
        // Single file output
        inlineDynamicImports: true,
        // Keep the bundle self-contained
        manualChunks: undefined,
      },
    },

    // Inline assets as base64
    assetsInlineLimit: 100000,

    // Minify for smaller bundle (use esbuild which is built-in)
    minify: 'esbuild',

    // Source maps for debugging
    sourcemap: true,

    // Target modern browsers (WebView2 on Windows supports modern JS)
    target: 'esnext',
  },

  // Resolve aliases
  resolve: {
    alias: {
      '@': path.resolve(__dirname, '.'),
    },
  },

  // Define environment variables
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
});
