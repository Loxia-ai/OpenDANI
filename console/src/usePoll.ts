import { useCallback, useEffect, useState } from "react";

// usePoll fetches on mount and every `ms`, exposing data/error/loading + a manual refresh. `key`
// re-arms the poll when the caller's query parameters change (e.g. the audit filter).
export function usePoll<T>(fn: () => Promise<T>, ms = 4000, key = "") {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      setData(await fn());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
    // fn identity is owned by the caller; key re-arms it when its inputs change
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      if (alive) await refresh();
    };
    tick();
    const id = setInterval(tick, ms);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [refresh, ms]);

  return { data, error, loading, refresh };
}
