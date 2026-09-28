import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import './ui-refresh.css';
import './ui-refresh-ai.css';
import './ui-refresh-dashboard.css';
import App from './App';

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
