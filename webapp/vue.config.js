module.exports = {
    devServer: {
        proxy: {
          '^/api': {
              target: 'http://ghidra:8000/',
                ws: true,
                changeOrigin: true
            }
        }
    },
}

