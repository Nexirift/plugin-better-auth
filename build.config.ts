import { defineBuildConfig } from 'unbuild';

export default defineBuildConfig({
	rollup: {
		emitCJS: true,
		esbuild: {
			treeShaking: true
		}
	},
	declaration: true,
	outDir: 'dist',
	clean: true,
	failOnWarn: false,
	externals: ['graphql-yoga', 'graphql', 'better-auth', 'redis', 'ioredis'],
	entries: ['src/index.ts']
});
