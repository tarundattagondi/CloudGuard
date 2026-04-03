import axios from 'axios';

const client = axios.create({
  baseURL: 'http://localhost:8000/api',
});

export const fetchSummary = () => client.get('/summary').then(res => res.data);
export const fetchScanAll = () => client.get('/scan').then(res => res.data);
export const fetchScanService = (service) => client.get(`/scan/${service}`).then(res => res.data);
export const fetchNistMapping = () => client.get('/nist-mapping').then(res => res.data);

export default client;
