import { useEffect, useState } from 'react';
import { commercialAPI, defaultBranding, type CommercialBranding } from '@/api/commercial';

let cachedBranding: CommercialBranding | null = null;
let inFlight: Promise<CommercialBranding> | null = null;

function mergeBranding(value: Partial<CommercialBranding>): CommercialBranding {
  return { ...defaultBranding, ...value };
}

function createBrandingEvent(value: CommercialBranding): Event {
  if (typeof window.CustomEvent === 'function') {
    return new CustomEvent('commercial:branding-updated', { detail: value });
  }
  const event = document.createEvent('Event') as Event & { detail?: CommercialBranding };
  event.initEvent('commercial:branding-updated', false, false);
  event.detail = value;
  return event;
}

export function setCachedCommercialBranding(value: CommercialBranding) {
  cachedBranding = mergeBranding(value);
  applyBrandingToDocument(cachedBranding);
  window.dispatchEvent(createBrandingEvent(cachedBranding));
}

export async function loadCommercialBranding(force = false): Promise<CommercialBranding> {
  if (cachedBranding && !force) {
    return cachedBranding;
  }
  if (!inFlight || force) {
    inFlight = commercialAPI.getBranding()
      .then((response) => {
        cachedBranding = mergeBranding(response.data);
        return cachedBranding;
      })
      .catch(() => {
        cachedBranding = cachedBranding || defaultBranding;
        return cachedBranding;
      })
      .finally(() => {
        inFlight = null;
      });
  }
  return inFlight;
}

export function applyBrandingToDocument(branding: CommercialBranding) {
  document.title = branding.product_name || defaultBranding.product_name;

  const favicon = branding.favicon?.trim();
  if (!favicon) return;

  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.rel = 'icon';
    document.head.appendChild(link);
  }
  link.href = favicon;
}

export function useCommercialBranding() {
  const [branding, setBranding] = useState<CommercialBranding>(cachedBranding || defaultBranding);
  const [loading, setLoading] = useState(!cachedBranding);

  useEffect(() => {
    let cancelled = false;
    setLoading(!cachedBranding);
    void loadCommercialBranding()
      .then((value) => {
        if (!cancelled) {
          setBranding(value);
          applyBrandingToDocument(value);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    const onBrandingUpdated = (event: Event) => {
      const value = (event as CustomEvent<CommercialBranding>).detail || cachedBranding || defaultBranding;
      setBranding(value);
      applyBrandingToDocument(value);
    };
    window.addEventListener('commercial:branding-updated', onBrandingUpdated);
    return () => {
      cancelled = true;
      window.removeEventListener('commercial:branding-updated', onBrandingUpdated);
    };
  }, []);

  return { branding, loading };
}
