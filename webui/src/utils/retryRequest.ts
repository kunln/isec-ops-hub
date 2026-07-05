/**
 * 带重试机制的请求工具
 * 用于处理后端重启等临时性错误
 */

interface RetryOptions {
  /** 最大重试次数 */
  maxRetries?: number;
  /** 初始延迟时间(ms) */
  initialDelay?: number;
  /** 最大延迟时间(ms) */
  maxDelay?: number;
  /** 是否使用指数退避 */
  exponentialBackoff?: boolean;
}

const defaultOptions: RetryOptions = {
  maxRetries: 3,
  initialDelay: 1000,
  maxDelay: 10000,
  exponentialBackoff: true,
};

/**
 * 判断错误是否应该重试
 */
function shouldRetry(error: any): boolean {
  // 网络错误、超时错误应该重试
  if (error.code === 'ERR_NETWORK' || error.code === 'ECONNABORTED') {
    return true;
  }
  
  // 5xx 错误应该重试
  if (error.response?.status >= 500 && error.response?.status < 600) {
    return true;
  }
  
  // 503 Service Unavailable (后端重启时)
  if (error.response?.status === 503) {
    return true;
  }
  
  return false;
}

/**
 * 计算重试延迟时间
 */
function getRetryDelay(
  attempt: number,
  options: RetryOptions
): number {
  const { initialDelay = 1000, maxDelay = 10000, exponentialBackoff = true } = options;
  
  if (!exponentialBackoff) {
    return initialDelay;
  }
  
  const delay = Math.min(initialDelay * Math.pow(2, attempt), maxDelay);
  // 添加随机抖动，避免雷暴效应
  return delay + Math.random() * 1000;
}

/**
 * 等待指定时间
 */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * 带重试机制的请求包装器
 */
export async function retryRequest<T>(
  requestFn: () => Promise<T>,
  options: RetryOptions = {}
): Promise<T> {
  const opts = { ...defaultOptions, ...options };
  let lastError: any;
  
  for (let attempt = 0; attempt <= (opts.maxRetries || 0); attempt++) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;
      
      // 如果不应该重试，或者已经是最后一次尝试，直接抛出错误
      if (!shouldRetry(error) || attempt === opts.maxRetries) {
        throw error;
      }
      
      // 计算延迟时间并等待
      const delayMs = getRetryDelay(attempt, opts);
      console.log(`Request failed (attempt ${attempt + 1}/${opts.maxRetries}), retrying in ${Math.round(delayMs)}ms...`);
      await delay(delayMs);
    }
  }
  
  throw lastError;
}

/**
 * 创建一个带重试的 API 客户端包装器
 */
export function createRetryableClient<T extends Record<string, any>>(
  client: T,
  options: RetryOptions = {}
): T {
  const proxy = new Proxy(client, {
    get(target, prop) {
      const value = target[prop as keyof T];
      
      // 如果是函数，包装成带重试的版本
      if (typeof value === 'function') {
        return (...args: any[]) => {
          return retryRequest(() => value.apply(target, args), options);
        };
      }
      
      return value;
    },
  });
  
  return proxy;
}
