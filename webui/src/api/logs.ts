import client from './client';

export interface LogFileInfo {
  name: string;
  size: number;
  modified: number;
}

export interface LogListResponse {
  files: LogFileInfo[];
  log_dir: string;
}

export interface LogContentResponse {
  filename: string;
  content: string;
  total_lines: number;
  truncated: boolean;
}

export const logsAPI = {
  list: () =>
    client.get<LogListResponse>('/api/logs'),

  readLatest: (tail = 200) =>
    client.get<LogContentResponse>('/api/logs/latest', { params: { tail } }),

  read: (filename: string, tail = 200) =>
    client.get<LogContentResponse>(`/api/logs/${filename}`, { params: { tail } }),
};
