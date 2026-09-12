import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: "https://niklasrosenstein.github.io",
  base: "/tlb",
  trailingSlash: "always",
  integrations: [
    starlight({
      title: "TLB",
      description: "Expose Kubernetes Services through Cloudflare Tunnel and NetBird.",
      logo: { src: "./src/assets/logo.svg", replacesTitle: false },
      favicon: "/favicon.svg",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/NiklasRosenstein/tlb" }],
      customCss: ["./src/styles/custom.css"],
      sidebar: [
        {
          label: "Start here",
          items: [
            { label: "Introduction", slug: "start/introduction" },
            { label: "Installation", slug: "start/installation" },
            { label: "Your first tunnel", slug: "start/quickstart" },
          ],
        },
        {
          label: "Guides",
          items: [
            { label: "Cloudflare Tunnel", slug: "guides/cloudflare" },
            { label: "NetBird", slug: "guides/netbird" },
            { label: "TLS and port mapping", slug: "guides/tls" },
          ],
        },
        {
          label: "Reference",
          items: [
            { label: "Tunnel classes", slug: "reference/classes" },
            { label: "Service annotations", slug: "reference/annotations" },
            { label: "Helm values", slug: "reference/helm" },
            { label: "Controller and CLI", slug: "reference/controller" },
          ],
        },
        {
          label: "Operations",
          items: [
            { label: "Security and ownership", slug: "operations/security" },
            { label: "Troubleshooting", slug: "operations/troubleshooting" },
            { label: "Development", slug: "operations/development" },
          ],
        },
      ],
    }),
  ],
});
