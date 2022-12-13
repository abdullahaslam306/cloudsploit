var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Public IP Address Has Tags',
    category: 'Virtual Networks',
    domain: 'IP Services',
    description: 'Ensures that Azure Public IP Address has tags.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Public IP address and add tags.',
    link: 'https://learn.microsoft.com/en-us/rest/api/virtualnetwork/public-ip-addresses/update-tags?tabs=HTTP',
    apis: ['publicIPAddresses:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.publicIPAddresses, function(location, rcb) {
            const publicAddresses = helpers.addSource(cache, source,
                ['publicIPAddresses', 'listAll', location]);

            if (!publicAddresses) return rcb();

            if (publicAddresses.err || !publicAddresses.data) {
                helpers.addResult(results, 3, 'Unable to query public IP addresses: ' + helpers.addError(publicAddresses), location);
                return rcb();
            }

            if (!publicAddresses.data.length) {
                helpers.addResult(results, 0, 'No public IP address found', location);
                return rcb();
            }

            for (let ip of publicAddresses.data) {
                if (!ip.id) continue;

                if (ip.tags && Object.entries(ip.tags).length > 0){
                    helpers.addResult(results, 0, 'Public IP has tags associated', location, ip.id);
                } else {
                    helpers.addResult(results, 2, 'Public IP does not have tags associated', location, ip.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};