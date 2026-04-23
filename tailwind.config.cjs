module.exports = {
  content: ["./ui/index.html", "./ui-src/**/*.{ts,html}"],
  theme: {
    extend: {
      colors: {
        ink: "#02030A",
        emeraldfx: "#22C55E",
        violetfx: "#A855F7",
        magentafx: "#E879F9"
      },
      boxShadow: {
        glow: "0 0 0 0.0625rem rgba(34,197,94,0.08), 0 1.5rem 5rem rgba(0,0,0,0.45)",
        panel: "0 1.125rem 3.75rem rgba(0,0,0,0.4)"
      },
      keyframes: {
        floaty: {
          "0%, 100%": { transform: "translate3d(0,0,0) scale(1)" },
          "50%": { transform: "translate3d(0.75rem,-0.625rem,0) scale(1.04)" }
        },
        pulseflow: {
          "0%": { opacity: "0.3", strokeDashoffset: "0" },
          "100%": { opacity: "0.95", strokeDashoffset: "-120" }
        },
        breathe: {
          "0%, 100%": { transform: "scale(1)", opacity: "0.68" },
          "50%": { transform: "scale(1.08)", opacity: "1" }
        }
      },
      animation: {
        floaty: "floaty 12s ease-in-out infinite",
        pulseflow: "pulseflow 8s linear infinite",
        breathe: "breathe 4s ease-in-out infinite"
      }
    }
  },
  plugins: []
};
