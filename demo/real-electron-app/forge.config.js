// Trusted, owned fixture only. This configuration is intentionally executable
// and is never auto-evaluated by the FEA scanner or its preview/apply modules.
const { FusesPlugin } = require('@electron-forge/plugin-fuses');
const { FuseVersion, FuseV1Options } = require('@electron/fuses');
module.exports = {
  packagerConfig: { name:'FEAElectronSmoke', executableName:'FEAElectronSmoke', asar:true },
  rebuildConfig: {},
  makers: [],
  plugins: [new FusesPlugin({
    version:FuseVersion.V1,
    [FuseV1Options.RunAsNode]:false,
    [FuseV1Options.EnableNodeOptionsEnvironmentVariable]:false,
    [FuseV1Options.EnableNodeCliInspectArguments]:false,
    [FuseV1Options.EnableEmbeddedAsarIntegrityValidation]:true,
    [FuseV1Options.OnlyLoadAppFromAsar]:true
  })]
};
