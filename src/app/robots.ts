import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        // Secret links must never be crawled, and the API must never be probed by bots.
        disallow: ["/s/", "/api/"],
      },
    ],
  };
}
