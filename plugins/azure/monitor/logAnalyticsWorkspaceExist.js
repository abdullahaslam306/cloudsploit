const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Analytics WorkSpace Exits',
    category: 'Monitor',
    domain: 'Management and Governance',
    description: 'Ensures that Microsoft Azure Log Analytics Workspace Exits.',
    more_info: 'A Log Analytics workspace is a unique environment for log data from Azure Monitor and other Azure services.Each workspace has its own data repository and configuration but might combine data from multiple services.',
    recommended_action: 'Ensure that Log Analytics Workspace exists in your azure account.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-workspace-overview',
    apis: ['workspaces:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        let workspaceExist = false;

        async.each(locations.workspaces, (location, rcb) => {
            const workspaces = helpers.addSource(cache, source,
                ['workspaces', 'list', location]);

            if (!workspaces) return rcb();

            if (workspaces.err || !workspaces.data) {
                helpers.addResult(results, 3, 'Unable to query for log analytics workspace: ' + helpers.addError(workspaces), location);
                return rcb();
            }

            if (!workspaces.data.length) {
                workspaceExist = true;
            }

            rcb();
        }, function() {
            if(workspaceExist){ 
                helpers.addResult(results, 0, 'Log Analytics workspace exist');
            } else {
                helpers.addResult(results, 2, 'Log Analytics workspace not exist');
            }
            callback(null, results, source);
        });
    }
};
