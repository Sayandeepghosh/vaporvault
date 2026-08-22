/**
 * Test stub for the `server-only` package.
 *
 * In a real build that import is what makes Next fail the build if server code is pulled
 * into a client bundle. Under Vitest there is no RSC graph, so it resolves to nothing.
 */
export {};
