var expect = require('chai').expect;
var logAnalyticsWorkspaceExist = require('./logAnalyticsWorkspaceExist');

const workspaces = [
    {
        "id": "/subscriptions/123/resourcegroups/oiautorest6685/providers/microsoft.operationalinsights/workspaces/aztest2170",
        "name": "AzTest2170",
        "type": "Microsoft.OperationalInsights/workspaces",
        "location": "eastus",
    }
];

const createCache = (workspace) => {
    return {
        workspaces: {
            list: {
                'eastus': { "data": workspace}
            }
        }
    };
};

describe('logAnalyticsWorkspaceExist', function() {
    describe('run', function() {
        it('should give unknown result if unable to query for workspace', function(done) {
            const cache = createCache(null);
            logAnalyticsWorkspaceExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for log analytics workspace:');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give passing result if workspace exists', function(done) {
            const cache = createCache([workspaces[0]]);
            logAnalyticsWorkspaceExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log Analytics workspace exist');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give failing result if logs are not enabled for all appropriate categories', function(done) {
            const cache = createCache([]);
            logAnalyticsWorkspaceExist.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log Analytics workspace not exist');
                expect(results[0].region).to.equal('global');
                done();
            });
        });
    });
});
