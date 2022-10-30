var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster Has Tags',
    category: 'Redshift',
    domain: 'Databases',
    description: 'Ensures that Amazon Redshift clusters Has Tags.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/amazon-redshift-tagging.html',
    recommended_action: 'Update Redshift cluster and add tags',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            for (let cluster of describeClusters.data) {
                if (!cluster.ClusterIdentifier) continue;

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.Tags && cluster.Tags.length) {
                    helpers.addResult(results, 0, 'Redshift cluster has tags', region, resource);    
                } else {
                    helpers.addResult(results, 2, 'Redshift cluster has no tags', region, resource);
                }
            };
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
