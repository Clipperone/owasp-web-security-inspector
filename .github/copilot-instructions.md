# Project Context
This project is a local browser extension for HTTP headers, cookies, and JWT token analysis.
It runs entirely locally with NO backend and NO external network calls for data processing.

# Tech Stack
- Vite
- React
- TypeScript (Strict Mode)
- Tailwind CSS
- Chrome Extension Manifest V3

# Global Rules
- **Manifest V3 Only**: Use `chrome.declarativeNetRequest` for network manipulation. Do not use deprecated Manifest V2 APIs like `chrome.webRequest.onBeforeSendHeaders` blocking.
- **Local Only**: All JWT decoding and parsing must be done natively using pure JavaScript/TypeScript (Base64Url decode). DO NOT install libraries like `jsonwebtoken` or `jwt-decode`.
- **Language**: All code, comments, variables, and the User Interface must be written in English.
- **UI/UX**: Build compact UI components tailored for an extension popup/devtools panel. Use Tailwind CSS for all styling.
- **Code Quality**: Write modular code using the Single Responsibility Principle. Handle errors silently in background scripts to prevent crashes.