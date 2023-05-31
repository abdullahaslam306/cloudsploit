const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Variables Encryption Enabled',
    category: 'Automation Account',
    domain: 'Automation',
    description: 'Ensure that Azure Automation Account Variables are Encrypted.',
    more_info: 'Azure Automation has the ability to share variable assets across runbooks and configurations. In doing so, it is considered best practice to encrypt these variables to ensure that sensitive information and intellectual property is protected.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/shared-resources/variables',
    recommended_action: 'Remove the unencrypted variable and recreate new variable with encryption enabled.',
    apis: ['automationAccount:list', 'variables:listByAutomationAccount'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.variables, function(location, rcb) {
            const automationAccount = helpers.addSource(cache, source,
                ['automationAccount', 'list', location]);

            if (!automationAccount) return rcb();

            if (automationAccount.err || !automationAccount.data) {
                helpers.addResult(results, 3, 'Unable to query for automation accounts: ' + helpers.addError(automationAccount), location);
                return rcb();
            }
            if (!automationAccount.data.length) {
                helpers.addResult(results, 0, 'No existing automation accounts found', location);
                return rcb();
            }

            for (let app of automationAccount.data) {
                if (!app.id) continue;

                const variables = helpers.addSource(cache, source,
                    ['variables', 'listByAutomationAccount', location, app.id]);

                if (!variables || variables.err || !variables.data) {
                    helpers.addResult(results, 3, 'Unable to query for automation account\'s variables: ' + helpers.addError(variables), location);
                    continue;
                }

                if (!variables.data.length) {
                    helpers.addResult(results, 0, 'No existing variables found', location);
                    continue;
                }
                
                for (let item of variables.data) {
                    if (item.isEncrypted) {
                        helpers.addResult(results, 0, 'Automation account variable is encrypted', location, item.id);
                    } else {
                        helpers.addResult(results, 2, 'Automation account variable is not encrypted', location, item.id);
                    }
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
