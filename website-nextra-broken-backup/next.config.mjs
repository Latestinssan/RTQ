import nextra from "nextra";

const withNextra = nextra({
  // Nextra 4.x: theme is configured in app/layout.tsx, not here
});

export default withNextra({
  reactStrictMode: true,
});
