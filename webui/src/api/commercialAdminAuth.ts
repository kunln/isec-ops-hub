import client from './client';
import type { LocalUser } from './auth';

export const commercialAdminAuthApi = {
  login: async (payload: { username: string; password: string }): Promise<LocalUser> => {
    const response = await client.post('/api/commercial-admin/auth/login', payload);
    return response.data;
  },

  me: async (): Promise<LocalUser> => {
    const response = await client.get('/api/commercial-admin/auth/me');
    return response.data;
  },

  logout: async (): Promise<void> => {
    await client.post('/api/commercial-admin/auth/logout');
  },
};
