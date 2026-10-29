import profiles from "../../cloudflare-profiles.json" with { type: "json" };

// Parsed as plain configuration by the pinned cf CLI and Vitest loader.
export default profiles.certified;
