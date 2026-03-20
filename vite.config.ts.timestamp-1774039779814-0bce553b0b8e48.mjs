// vite.config.ts
import { defineConfig } from "file:///C:/Users/ffavara/Documents/Sviluppo/cookie-token-header-editor/node_modules/vite/dist/node/index.js";
import react from "file:///C:/Users/ffavara/Documents/Sviluppo/cookie-token-header-editor/node_modules/@vitejs/plugin-react/dist/index.js";
import { crx } from "file:///C:/Users/ffavara/Documents/Sviluppo/cookie-token-header-editor/node_modules/@crxjs/vite-plugin/dist/index.mjs";

// manifest.json
var manifest_default = {
  manifest_version: 3,
  name: "Cookie / Token / Header Editor",
  version: "0.1.0",
  description: "Analyze and manipulate cookies, JWT tokens, and HTTP headers directly in your browser.",
  permissions: [
    "declarativeNetRequest",
    "declarativeNetRequestWithHostAccess",
    "storage",
    "cookies",
    "scripting",
    "activeTab",
    "webRequest"
  ],
  host_permissions: ["<all_urls>"],
  action: {
    default_popup: "src/popup/index.html",
    default_title: "Cookie / Token / Header Editor",
    default_icon: {
      "16": "icons/icon16.png",
      "32": "icons/icon32.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  background: {
    service_worker: "src/background/index.ts",
    type: "module"
  },
  content_scripts: [
    {
      matches: ["<all_urls>"],
      js: ["src/content/index.ts"],
      run_at: "document_idle"
    }
  ],
  icons: {
    "16": "icons/icon16.png",
    "32": "icons/icon32.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  },
  declarative_net_request: {
    rule_resources: []
  }
};

// vite.config.ts
var vite_config_default = defineConfig({
  plugins: [
    react(),
    crx({ manifest: manifest_default })
  ],
  build: {
    sourcemap: true
  }
});
export {
  vite_config_default as default
};
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsidml0ZS5jb25maWcudHMiLCAibWFuaWZlc3QuanNvbiJdLAogICJzb3VyY2VzQ29udGVudCI6IFsiY29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2Rpcm5hbWUgPSBcIkM6XFxcXFVzZXJzXFxcXGZmYXZhcmFcXFxcRG9jdW1lbnRzXFxcXFN2aWx1cHBvXFxcXGNvb2tpZS10b2tlbi1oZWFkZXItZWRpdG9yXCI7Y29uc3QgX192aXRlX2luamVjdGVkX29yaWdpbmFsX2ZpbGVuYW1lID0gXCJDOlxcXFxVc2Vyc1xcXFxmZmF2YXJhXFxcXERvY3VtZW50c1xcXFxTdmlsdXBwb1xcXFxjb29raWUtdG9rZW4taGVhZGVyLWVkaXRvclxcXFx2aXRlLmNvbmZpZy50c1wiO2NvbnN0IF9fdml0ZV9pbmplY3RlZF9vcmlnaW5hbF9pbXBvcnRfbWV0YV91cmwgPSBcImZpbGU6Ly8vQzovVXNlcnMvZmZhdmFyYS9Eb2N1bWVudHMvU3ZpbHVwcG8vY29va2llLXRva2VuLWhlYWRlci1lZGl0b3Ivdml0ZS5jb25maWcudHNcIjtpbXBvcnQgeyBkZWZpbmVDb25maWcgfSBmcm9tICd2aXRlJztcclxuaW1wb3J0IHJlYWN0IGZyb20gJ0B2aXRlanMvcGx1Z2luLXJlYWN0JztcclxuaW1wb3J0IHsgY3J4IH0gZnJvbSAnQGNyeGpzL3ZpdGUtcGx1Z2luJztcclxuaW1wb3J0IG1hbmlmZXN0IGZyb20gJy4vbWFuaWZlc3QuanNvbic7XHJcblxyXG4vLyBodHRwczovL3ZpdGVqcy5kZXYvY29uZmlnL1xyXG5leHBvcnQgZGVmYXVsdCBkZWZpbmVDb25maWcoe1xyXG4gIHBsdWdpbnM6IFtcclxuICAgIHJlYWN0KCksXHJcbiAgICBjcngoeyBtYW5pZmVzdCB9KSxcclxuICBdLFxyXG4gIGJ1aWxkOiB7XHJcbiAgICBzb3VyY2VtYXA6IHRydWUsXHJcbiAgfSxcclxufSk7XHJcbiIsICJ7XHJcbiAgXCJtYW5pZmVzdF92ZXJzaW9uXCI6IDMsXHJcbiAgXCJuYW1lXCI6IFwiQ29va2llIC8gVG9rZW4gLyBIZWFkZXIgRWRpdG9yXCIsXHJcbiAgXCJ2ZXJzaW9uXCI6IFwiMC4xLjBcIixcclxuICBcImRlc2NyaXB0aW9uXCI6IFwiQW5hbHl6ZSBhbmQgbWFuaXB1bGF0ZSBjb29raWVzLCBKV1QgdG9rZW5zLCBhbmQgSFRUUCBoZWFkZXJzIGRpcmVjdGx5IGluIHlvdXIgYnJvd3Nlci5cIixcclxuXHJcbiAgXCJwZXJtaXNzaW9uc1wiOiBbXHJcbiAgICBcImRlY2xhcmF0aXZlTmV0UmVxdWVzdFwiLFxyXG4gICAgXCJkZWNsYXJhdGl2ZU5ldFJlcXVlc3RXaXRoSG9zdEFjY2Vzc1wiLFxyXG4gICAgXCJzdG9yYWdlXCIsXHJcbiAgICBcImNvb2tpZXNcIixcclxuICAgIFwic2NyaXB0aW5nXCIsXHJcbiAgICBcImFjdGl2ZVRhYlwiLFxyXG4gICAgXCJ3ZWJSZXF1ZXN0XCJcclxuICBdLFxyXG5cclxuICBcImhvc3RfcGVybWlzc2lvbnNcIjogW1wiPGFsbF91cmxzPlwiXSxcclxuXHJcbiAgXCJhY3Rpb25cIjoge1xyXG4gICAgXCJkZWZhdWx0X3BvcHVwXCI6IFwic3JjL3BvcHVwL2luZGV4Lmh0bWxcIixcclxuICAgIFwiZGVmYXVsdF90aXRsZVwiOiBcIkNvb2tpZSAvIFRva2VuIC8gSGVhZGVyIEVkaXRvclwiLFxyXG4gICAgXCJkZWZhdWx0X2ljb25cIjoge1xyXG4gICAgICBcIjE2XCI6ICBcImljb25zL2ljb24xNi5wbmdcIixcclxuICAgICAgXCIzMlwiOiAgXCJpY29ucy9pY29uMzIucG5nXCIsXHJcbiAgICAgIFwiNDhcIjogIFwiaWNvbnMvaWNvbjQ4LnBuZ1wiLFxyXG4gICAgICBcIjEyOFwiOiBcImljb25zL2ljb24xMjgucG5nXCJcclxuICAgIH1cclxuICB9LFxyXG5cclxuICBcImJhY2tncm91bmRcIjoge1xyXG4gICAgXCJzZXJ2aWNlX3dvcmtlclwiOiBcInNyYy9iYWNrZ3JvdW5kL2luZGV4LnRzXCIsXHJcbiAgICBcInR5cGVcIjogXCJtb2R1bGVcIlxyXG4gIH0sXHJcblxyXG4gIFwiY29udGVudF9zY3JpcHRzXCI6IFtcclxuICAgIHtcclxuICAgICAgXCJtYXRjaGVzXCI6IFtcIjxhbGxfdXJscz5cIl0sXHJcbiAgICAgIFwianNcIjogW1wic3JjL2NvbnRlbnQvaW5kZXgudHNcIl0sXHJcbiAgICAgIFwicnVuX2F0XCI6IFwiZG9jdW1lbnRfaWRsZVwiXHJcbiAgICB9XHJcbiAgXSxcclxuXHJcbiAgXCJpY29uc1wiOiB7XHJcbiAgICBcIjE2XCI6ICBcImljb25zL2ljb24xNi5wbmdcIixcclxuICAgIFwiMzJcIjogIFwiaWNvbnMvaWNvbjMyLnBuZ1wiLFxyXG4gICAgXCI0OFwiOiAgXCJpY29ucy9pY29uNDgucG5nXCIsXHJcbiAgICBcIjEyOFwiOiBcImljb25zL2ljb24xMjgucG5nXCJcclxuICB9LFxyXG5cclxuICBcImRlY2xhcmF0aXZlX25ldF9yZXF1ZXN0XCI6IHtcclxuICAgIFwicnVsZV9yZXNvdXJjZXNcIjogW11cclxuICB9XHJcbn1cclxuIl0sCiAgIm1hcHBpbmdzIjogIjtBQUF3WCxTQUFTLG9CQUFvQjtBQUNyWixPQUFPLFdBQVc7QUFDbEIsU0FBUyxXQUFXOzs7QUNGcEI7QUFBQSxFQUNFLGtCQUFvQjtBQUFBLEVBQ3BCLE1BQVE7QUFBQSxFQUNSLFNBQVc7QUFBQSxFQUNYLGFBQWU7QUFBQSxFQUVmLGFBQWU7QUFBQSxJQUNiO0FBQUEsSUFDQTtBQUFBLElBQ0E7QUFBQSxJQUNBO0FBQUEsSUFDQTtBQUFBLElBQ0E7QUFBQSxJQUNBO0FBQUEsRUFDRjtBQUFBLEVBRUEsa0JBQW9CLENBQUMsWUFBWTtBQUFBLEVBRWpDLFFBQVU7QUFBQSxJQUNSLGVBQWlCO0FBQUEsSUFDakIsZUFBaUI7QUFBQSxJQUNqQixjQUFnQjtBQUFBLE1BQ2QsTUFBTztBQUFBLE1BQ1AsTUFBTztBQUFBLE1BQ1AsTUFBTztBQUFBLE1BQ1AsT0FBTztBQUFBLElBQ1Q7QUFBQSxFQUNGO0FBQUEsRUFFQSxZQUFjO0FBQUEsSUFDWixnQkFBa0I7QUFBQSxJQUNsQixNQUFRO0FBQUEsRUFDVjtBQUFBLEVBRUEsaUJBQW1CO0FBQUEsSUFDakI7QUFBQSxNQUNFLFNBQVcsQ0FBQyxZQUFZO0FBQUEsTUFDeEIsSUFBTSxDQUFDLHNCQUFzQjtBQUFBLE1BQzdCLFFBQVU7QUFBQSxJQUNaO0FBQUEsRUFDRjtBQUFBLEVBRUEsT0FBUztBQUFBLElBQ1AsTUFBTztBQUFBLElBQ1AsTUFBTztBQUFBLElBQ1AsTUFBTztBQUFBLElBQ1AsT0FBTztBQUFBLEVBQ1Q7QUFBQSxFQUVBLHlCQUEyQjtBQUFBLElBQ3pCLGdCQUFrQixDQUFDO0FBQUEsRUFDckI7QUFDRjs7O0FEOUNBLElBQU8sc0JBQVEsYUFBYTtBQUFBLEVBQzFCLFNBQVM7QUFBQSxJQUNQLE1BQU07QUFBQSxJQUNOLElBQUksRUFBRSwyQkFBUyxDQUFDO0FBQUEsRUFDbEI7QUFBQSxFQUNBLE9BQU87QUFBQSxJQUNMLFdBQVc7QUFBQSxFQUNiO0FBQ0YsQ0FBQzsiLAogICJuYW1lcyI6IFtdCn0K
