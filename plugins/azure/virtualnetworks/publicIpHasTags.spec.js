var expect = require('chai').expect;
var publicIpHasTags = require('./publicIpHasTags');

const listIP = [
    {
    name: 'aqua-test',
    id: '/subscriptions/123/resourceGroups/aqua_satest_centralus/providers/Microsoft.Network/publicIPAddresses/aqua-test',
    etag: 'W/"123-123"',
    location: 'centralus',
    tags: {
      'key': 'value'
    },
    zones: [ '1', '3', '2' ],
    type: 'Microsoft.Network/publicIPAddresses',
    sku: { name: 'Standard', tier: 'Regional' },
    provisioningState: 'Succeeded',
    },
    {
    name: 'aqua-test',
    id: '/subscriptions/123/resourceGroups/aqua_satest_centralus/providers/Microsoft.Network/publicIPAddresses/aqua-test',
    etag: 'W/"123-123"',
    location: 'centralus',
    tags: {},
    zones: [ '1', '3', '2' ],
    type: 'Microsoft.Network/publicIPAddresses',
    sku: { name: 'Standard', tier: 'Regional' },
    provisioningState: 'Succeeded',
    }
];

const createCache = (iplist, err) => {
    return {
        publicIPAddresses: {
            listAll: {
                'eastus': {
                    err: err,
                    data: iplist
                }
            }
        }
    }
};

describe('publicIpHasTags', function() {
    describe('run', function() {
        it('should give passing result if No public IP address found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No public IP address found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([]);
            publicIpHasTags.run(cache, {}, callback);
        });

        it('should give failing result if Public IP does not have tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Public IP does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([listIP[1]]);
            publicIpHasTags.run(cache, {}, callback);
        });

        it('should give passing result if Public IP has tags associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Public IP has tags associated');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listIP[0]]
            );

            publicIpHasTags.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query public IP addresses', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query public IP addresses:');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(listIP,{ message: 'unable to query Virtual Networks'});
            publicIpHasTags.run(cache, {}, callback);
        });
    })
})