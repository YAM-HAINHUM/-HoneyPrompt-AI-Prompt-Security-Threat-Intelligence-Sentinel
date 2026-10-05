import { useEffect, useRef, useState } from 'react';

export default function CountdownTimer({ until, onExpire }) {
  const [now, setNow] = useState(0);
  const expirationHandled = useRef(false);
  const deadline = new Date(until).getTime();
  const remaining = Math.max(0, Math.ceil((deadline - now) / 1000));

  useEffect(() => {
    const sync = window.setTimeout(() => setNow(Date.now()), 0);
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearTimeout(sync);
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => { expirationHandled.current = false; }, [until]);
  useEffect(() => {
    if (now > 0 && remaining === 0 && !expirationHandled.current) {
      expirationHandled.current = true;
      onExpire?.();
    }
  }, [now, remaining, onExpire]);

  const minutes = Math.floor(remaining / 60).toString().padStart(2, '0');
  const seconds = (remaining % 60).toString().padStart(2, '0');
  return <time dateTime={until}>Chat available again in {now === 0 ? '--:--' : `${minutes}:${seconds}`}</time>;
}