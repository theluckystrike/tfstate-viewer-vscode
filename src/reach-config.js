'use strict';
module.exports = {
  prefix: 'zovoTfstate',
  triesKey: 'zovoTfstate.proTrial',
  slot: '#protools',
  tools: [
    { id: 'diffStates', title: 'Compare two Terraform state or plan files', command: 'zovoTfstate.diffStates' },
    { id: 'auditSecrets', title: 'Audit Terraform state secrets and public exposure', command: 'zovoTfstate.auditSecrets' },
    { id: 'exportInventory', title: 'Export Terraform inventory to CSV, JSON and Mermaid', command: 'zovoTfstate.exportInventory' },
  ],
};
