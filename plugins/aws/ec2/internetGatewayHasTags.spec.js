var expect = require('chai').expect;
const internetGatewayHasTags = require('./internetGatewayHasTags');

const describeInternetGateways = [
    {
        "InternetGatewayId": "igw-7f3e1a04",
        "OwnerId": "111122223333",
        "Tags": []
    },
    {
        "InternetGatewayId": "igw-0a82fd444d2c310d1",
        "OwnerId": "111122223333",
        "Tags": [
            {
                "Key": "Name",
                "Value": "test-64"
            }
        ]
    }
];


const createCache = (ig) => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': {
                    data: ig
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeInternetGateways: {
                'us-east-1': {
                    err: {
                        message: 'error describing Internet Gateways'
                    },
                },
            },
        },
    };
};

describe('internetGatewayHasTags', function () {
    describe('run', function () {
        it('should PASS if Internet Gateway has tags', function (done) {
            const cache = createCache([describeInternetGateways[1]]);
            internetGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Internet Gateway does not have tags', function (done) {
            const cache = createCache([describeInternetGateways[0]]);
            internetGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for Internet Gateways', function (done) {
            const cache = createErrorCache();
            internetGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Internet Gateways found', function (done) {
            const cache = createCache([]);
            internetGatewayHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

    });
});