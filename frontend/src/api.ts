import axios from 'axios';

const baseURL = import.meta.env.VITE_API_URL || 'http://148.100.98.173:8000';

const api = axios.create({
  baseURL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const getSystemStatus = async () => {
  const response = await api.get('/api/system/status');
  return response.data;
};

export const getModelStatus = async () => {
  const response = await api.get('/api/model/status');
  return response.data;
};

export const getAlerts = async () => {
  const response = await api.get('/api/alerts');
  return response.data;
};

export const triggerNormalAccess = async () => {
  const response = await api.post('/api/demo/normal-access');
  return response.data;
};

export const triggerSuspiciousAccess = async () => {
  const response = await api.post('/api/demo/suspicious-access');
  return response.data;
};

export const triggerUnauthorizedExport = async () => {
  const response = await api.post('/api/demo/unauthorized-export');
  return response.data;
};
