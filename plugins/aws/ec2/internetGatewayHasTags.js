var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Internet Gateways Has Tags',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure that Internet Gateway have tags',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-ec2-internetgateway.html',
    recommended_action: 'Modify Internet Gateway and Add new tags.',
    apis: ['EC2:describeInternetGateways', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeInternetGateways = helpers.addSource(cache, source,
                ['ec2', 'describeInternetGateways', region]);

            if (!describeInternetGateways) return rcb();

            if (describeInternetGateways.err || !describeInternetGateways.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Internet Gateways: ${helpers.addError(describeInternetGateways)}`,
                    region);
                return rcb();
            }

            if (!describeInternetGateways.data.length) {
                helpers.addResult(results, 0, 'No Internet Gateways found', region);
                return rcb();
            }

            for (let gateway of  describeInternetGateways.data) {
                let arn = `arn:${awsOrGov}:vpc:${region}:${accountId}:internet-gateway/${gateway.InternetGatewayId}`;
                
                if (!gateway.Tags ||  gateway.Tags.length === 0) {
                    helpers.addResult(results, 2, 'Internet Gateway has no tags.', region, arn);
                } else {
                    helpers.addResult(results, 0, 'Internet Gateway has tags.', region, arn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};