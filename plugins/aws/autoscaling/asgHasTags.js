var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ASG have tags',
    category: 'AutoScaling',
    domain: 'Availability',
    description: 'Ensure that Auto Scaling Groups have tags',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-tagging.html',
    recommended_action: 'Modify the autoscaling group and add tags.',
    apis: ['AutoScaling:describeAutoScalingGroups'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for auto scaling groups: ' + 
                    helpers.addError(describeAutoScalingGroups), region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No auto scaling groups found', region);
                return rcb();
            }

        
            for (let asg of describeAutoScalingGroups.data) {
                if (!asg.Tags || !asg.Tags.length) {
                    helpers.addResult(results, 2, 'Auto Scaling group has no tags associated', region, asg.AutoScalingGroupARN);
                } else {
                    helpers.addResult(results, 0, 'Auto Scaling group has tags', region, asg.AutoScalingGroupARN);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
