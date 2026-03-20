import React from 'react';
import ReactDOM from 'react-dom/client';
import { NetworkPanel } from './NetworkPanel';
import '../popup/index.css';

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <NetworkPanel />
  </React.StrictMode>,
);
