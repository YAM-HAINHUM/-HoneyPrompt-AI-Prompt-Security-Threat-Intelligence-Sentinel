import { useEffect, useRef } from 'react';

export default function HoneyBeeBackground() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const motionQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

    let W = window.innerWidth;
    let H = window.innerHeight;
    canvas.width = W;
    canvas.height = H;

    const mouse = { x: -999, y: -999 };

    // Bee state
    const bee = {
      x: W * 0.7, y: H * 0.3,
      vx: 0.6, vy: 0.4,
      targetX: W * 0.7, targetY: H * 0.3,
      wingAngle: 0, wingDir: 1,
      trail: [],
    };

    // Particles
    const particles = Array.from({ length: 28 }, () => ({
      x: Math.random() * W, y: Math.random() * H,
      r: Math.random() * 2 + 0.5,
      vx: (Math.random() - 0.5) * 0.3,
      vy: (Math.random() - 0.5) * 0.3,
      alpha: Math.random() * 0.4 + 0.1,
    }));

    // Honeycomb cells (static background)
    const hexCells = [];
    const hexSize = 38;
    const hexW = hexSize * 2;
    const hexH = Math.sqrt(3) * hexSize;
    const populateHexCells = () => {
      hexCells.length = 0;
      for (let row = -1; row < H / hexH + 2; row++) {
        for (let col = -1; col < W / hexW + 2; col++) {
          const x = col * hexW * 0.75;
          const y = row * hexH + (col % 2 === 0 ? 0 : hexH / 2);
          hexCells.push({ x, y });
        }
      }
    };
    populateHexCells();

    let animId;
    let tick = 0;

    const drawHex = (cx, cy, size, alpha) => {
      ctx.beginPath();
      for (let i = 0; i < 6; i++) {
        const angle = (Math.PI / 3) * i - Math.PI / 6;
        const px = cx + size * Math.cos(angle);
        const py = cy + size * Math.sin(angle);
        i === 0 ? ctx.moveTo(px, py) : ctx.lineTo(px, py);
      }
      ctx.closePath();
      ctx.strokeStyle = `rgba(245,197,24,${alpha})`;
      ctx.lineWidth = 0.5;
      ctx.stroke();
    };

    const drawBee = (x, y, wingAngle) => {
      ctx.save();
      ctx.translate(x, y);

      // Glow
      const grd = ctx.createRadialGradient(0, 0, 2, 0, 0, 22);
      grd.addColorStop(0, 'rgba(245,197,24,0.18)');
      grd.addColorStop(1, 'rgba(245,197,24,0)');
      ctx.fillStyle = grd;
      ctx.beginPath();
      ctx.arc(0, 0, 22, 0, Math.PI * 2);
      ctx.fill();

      // Wings
      ctx.save();
      ctx.rotate(-wingAngle * 0.5);
      ctx.beginPath();
      ctx.ellipse(-5, -7, 9, 5, -0.4, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(200,230,255,0.55)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(180,210,255,0.7)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
      ctx.restore();

      ctx.save();
      ctx.rotate(wingAngle * 0.5);
      ctx.beginPath();
      ctx.ellipse(5, -7, 9, 5, 0.4, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(200,230,255,0.55)';
      ctx.fill();
      ctx.strokeStyle = 'rgba(180,210,255,0.7)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
      ctx.restore();

      // Body
      ctx.beginPath();
      ctx.ellipse(0, 2, 5, 8, 0, 0, Math.PI * 2);
      ctx.fillStyle = '#F5C518';
      ctx.fill();

      // Stripes
      for (let i = 0; i < 3; i++) {
        ctx.beginPath();
        ctx.ellipse(0, -1 + i * 3.5, 4.5, 1.2, 0, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(20,10,0,0.7)';
        ctx.fill();
      }

      // Head
      ctx.beginPath();
      ctx.arc(0, -7, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#1a1000';
      ctx.fill();

      // Eyes
      ctx.beginPath();
      ctx.arc(-1.5, -8, 1, 0, Math.PI * 2);
      ctx.arc(1.5, -8, 1, 0, Math.PI * 2);
      ctx.fillStyle = '#F5C518';
      ctx.fill();

      // Stinger
      ctx.beginPath();
      ctx.moveTo(0, 10);
      ctx.lineTo(-1.5, 13);
      ctx.lineTo(1.5, 13);
      ctx.closePath();
      ctx.fillStyle = '#c8a000';
      ctx.fill();

      ctx.restore();
    };

    const loop = () => {
      const animate = !motionQuery.matches && !document.hidden;
      if (animate) tick++;
      ctx.clearRect(0, 0, W, H);

      // Honeycomb background
      hexCells.forEach(({ x, y }) => drawHex(x, y, hexSize, 0.045));

      // Particles
      particles.forEach(p => {
        if (animate) {
          p.x += p.vx; p.y += p.vy;
          if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
          if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
        }
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(245,197,24,${p.alpha})`;
        ctx.fill();
      });

      // Bee cursor avoidance
      const dx = bee.x - mouse.x;
      const dy = bee.y - mouse.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      const AVOID_RADIUS = 120;

      if (animate && dist < AVOID_RADIUS) {
        const force = (AVOID_RADIUS - dist) / AVOID_RADIUS;
        const safeDist = Math.max(dist, 1);
        bee.vx += (dx / safeDist) * force * 2.2;
        bee.vy += (dy / safeDist) * force * 2.2;
      }

      // Wander toward random target
      if (animate && tick % 180 === 0) {
        bee.targetX = 80 + Math.random() * (W - 160);
        bee.targetY = 80 + Math.random() * (H - 160);
      }
      if (animate) {
        bee.vx += (bee.targetX - bee.x) * 0.0008;
        bee.vy += (bee.targetY - bee.y) * 0.0008;
      }

      // Speed cap
      const speed = Math.sqrt(bee.vx * bee.vx + bee.vy * bee.vy);
      const MAX_SPEED = 2.8;
      if (animate && speed > MAX_SPEED) { bee.vx = (bee.vx / speed) * MAX_SPEED; bee.vy = (bee.vy / speed) * MAX_SPEED; }

      if (animate) {
        bee.x += bee.vx; bee.y += bee.vy;
        bee.vx *= 0.97; bee.vy *= 0.97;
      }

      // Bounce off edges
      const marginX = Math.min(60, W / 2);
      const marginY = Math.min(60, H / 2);
      if (animate && bee.x < marginX) { bee.x = marginX; bee.vx = Math.abs(bee.vx); }
      if (animate && bee.x > W - marginX) { bee.x = W - marginX; bee.vx = -Math.abs(bee.vx); }
      if (animate && bee.y < marginY) { bee.y = marginY; bee.vy = Math.abs(bee.vy); }
      if (animate && bee.y > H - marginY) { bee.y = H - marginY; bee.vy = -Math.abs(bee.vy); }

      // Wing flap
      if (animate) {
        bee.wingAngle += 0.28 * bee.wingDir;
        if (Math.abs(bee.wingAngle) > 0.55) bee.wingDir *= -1;
      }

      // Trail
      if (animate) {
        bee.trail.push({ x: bee.x, y: bee.y, alpha: 0.18 });
        if (bee.trail.length > 18) bee.trail.shift();
      }
      bee.trail.forEach((pt, i) => {
        const a = (i / bee.trail.length) * pt.alpha;
        ctx.beginPath();
        ctx.arc(pt.x, pt.y, 1.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(245,197,24,${a})`;
        ctx.fill();
      });

      drawBee(bee.x, bee.y, bee.wingAngle);
      if (animate) animId = requestAnimationFrame(loop);
    };

    loop();

    const onMove = (e) => { mouse.x = e.clientX; mouse.y = e.clientY; };
    const onResize = () => {
      W = window.innerWidth; H = window.innerHeight;
      canvas.width = W; canvas.height = H;
      bee.x = Math.min(Math.max(bee.x, Math.min(60, W / 2)), W - Math.min(60, W / 2));
      bee.y = Math.min(Math.max(bee.y, Math.min(60, H / 2)), H - Math.min(60, H / 2));
      populateHexCells();
      if (motionQuery.matches || document.hidden) loop();
    };
    const onMotionChange = () => {
      cancelAnimationFrame(animId);
      if (motionQuery.matches || document.hidden) loop();
      else loop();
    };
    const onVisibilityChange = () => {
      cancelAnimationFrame(animId);
      loop();
    };

    window.addEventListener('mousemove', onMove);
    window.addEventListener('resize', onResize);
    motionQuery.addEventListener('change', onMotionChange);
    document.addEventListener('visibilitychange', onVisibilityChange);

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('resize', onResize);
      motionQuery.removeEventListener('change', onMotionChange);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'fixed', inset: 0,
        width: '100%', height: '100%',
        pointerEvents: 'none',
        zIndex: 0,
        opacity: 0.85,
      }}
      aria-hidden="true"
    />
  );
}
