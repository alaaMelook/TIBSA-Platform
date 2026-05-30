import React, { useEffect, useState } from "react";

interface RiskGaugeProps {
  score: number; // 0 to 100
  size?: number;
}

export function RiskGauge({ score, size = 180 }: RiskGaugeProps) {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    // Animate score changes smoothly
    let start = animatedScore;
    const end = Math.min(100, Math.max(0, score));
    if (start === end) return;

    const duration = 800; // ms
    const stepTime = 16; // ~60fps
    const steps = duration / stepTime;
    const increment = (end - start) / steps;
    let currentStep = 0;

    const timer = setInterval(() => {
      currentStep++;
      start += increment;
      if (currentStep >= steps) {
        setAnimatedScore(end);
        clearInterval(timer);
      } else {
        setAnimatedScore(Math.round(start));
      }
    }, stepTime);

    return () => clearInterval(timer);
  }, [score]);

  // SVG calculations for a half-donut or full-donut. Let's do a elegant 3/4 gauge.
  const strokeWidth = 14;
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const angleRange = 270; // 3/4 circle
  const dashArray = circumference;
  const dashOffset = circumference - (animatedScore / 100) * circumference * (angleRange / 360);

  // Determine color based on current animated score
  const getRiskColor = (val: number) => {
    if (val <= 30) return "#10b981"; // Green (emerald-500)
    if (val <= 60) return "#eab308"; // Yellow (amber-500)
    if (val <= 80) return "#f97316"; // Orange (orange-500)
    return "#ef4444"; // Red (red-500)
  };

  const getRiskLabel = (val: number) => {
    if (val <= 30) return "LOW";
    if (val <= 60) return "MEDIUM";
    if (val <= 80) return "HIGH";
    return "CRITICAL";
  };

  const color = getRiskColor(animatedScore);
  const label = getRiskLabel(animatedScore);

  return (
    <div className="flex flex-col items-center justify-center select-none">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          className="transform -rotate-[225deg]" // Start from bottom-left
        >
          {/* Background track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={circumference - circumference * (angleRange / 360)}
            strokeLinecap="round"
          />

          {/* Foreground risk arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={dashArray}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            className="transition-all duration-300 ease-out"
          />
        </svg>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center mt-2">
          <span className="text-4xl font-extrabold text-white tracking-tight">
            {animatedScore}
          </span>
          <span
            className="text-[10px] font-bold tracking-wider uppercase mt-1 px-2.5 py-0.5 rounded-full border bg-opacity-10"
            style={{
              color: color,
              borderColor: `${color}33`,
              backgroundColor: `${color}15`,
            }}
          >
            {label}
          </span>
          <span className="text-[10px] text-slate-500 uppercase font-medium tracking-widest mt-1">
            Risk Index
          </span>
        </div>
      </div>
    </div>
  );
}
