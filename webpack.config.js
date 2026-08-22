'use strict';

const path            = require('path');
const webpack         = require('webpack');
const CopyPlugin      = require('copy-webpack-plugin');
const TerserPlugin    = require('terser-webpack-plugin');

const appVersion      = require('./package.json').version;
const mcborVersion    = require('@vanaheimr/metrological-cbor/package.json').version;
const coseVersion     = require('@vanaheimr/cose/package.json').version;

module.exports = {

    mode:    'production',
    entry:   './src/index.js',
    target:  ['web', 'es2022'],
    devtool: false,

    output: {
        path:     path.resolve(__dirname, 'dist'),
        filename: 'validator.js',
        clean:    true
    },

    plugins: [
        new webpack.DefinePlugin({
            __APP_VERSION__:   JSON.stringify(appVersion),
            __MCBOR_VERSION__: JSON.stringify(mcborVersion),
            __COSE_VERSION__:  JSON.stringify(coseVersion)
        }),
        new CopyPlugin({
            patterns: [
                { from: 'src/index.html', to: 'index.html' },
                { from: 'src/styles.css', to: 'styles.css' }
            ]
        })
    ],

    optimization: {
        minimizer: [
            new TerserPlugin({
                // Keep the /*! … */ license banners of the bundled libraries
                // inside validator.js instead of emitting a fourth file.
                extractComments: false,
                terserOptions: { format: { comments: /^\**!/ } }
            })
        ]
    },

    performance: {
        // The bundle carries the COSE algorithm registry and the @noble
        // cryptography underneath it; the size is intentional.
        hints: false
    }

};
