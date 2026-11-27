import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "GitSecure",
    short_name: "GitSecure",
    description:
      "Is this repo safe? Swap github.com for git-secure.com and get a plain-English security report.",
    start_url: "/",
    display: "standalone",
    background_color: "#0f143e",
    theme_color: "#0b6e4f",
    icons: [
      { src: "/icon.png", sizes: "512x512", type: "image/png" },
      { src: "/apple-icon.png", sizes: "180x180", type: "image/png" },
    ],
  };
}
