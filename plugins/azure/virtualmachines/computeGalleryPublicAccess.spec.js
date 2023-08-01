var expect = require('chai').expect;
var computeGalleryPublicAccess = require('./computeGalleryPublicAccess');

const computeGalleries = [
    { 
        "name": 'test',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/galleries/test",
        "type": "Microsoft.Compute/galleries",
        "location": "eastus",
        "properties": {
            "sharingProfile": {
                "permissions": "Private"
            },
            "provisioningState": "Succeeded"
      }
    },
   { 
        "name": 'test',
        "id": "/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Compute/galleries/test",
        "type": "Microsoft.Compute/galleries",
        "location": "eastus",
        "properties": {
            "sharingProfile": {
                "permissions": "Community"
            },
            "provisioningState": "Succeeded"
      }
    },
];

const createCache = (gallery) => {
    return {
        computeGallery: {
            listAll: {
                'eastus': {
                    data: gallery
                }
            }
        }
    };
};

describe('computeGalleryPublicAccess', function() {
    describe('run', function() {
        it('should give passing result if no gallery found', function(done) {
            const cache = createCache([]);
            computeGalleryPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Azure Compute Galleries found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for galleries', function(done) {
            const cache = createCache();
            computeGalleryPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Azure Compute Galleries:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if gallery is not publicly accessible', function(done) {
            const cache = createCache([computeGalleries[0]]);
            computeGalleryPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Azure Compute Gallery is not publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if gallery is publicly accessible', function(done) {
            const cache = createCache([computeGalleries[1]]);
            computeGalleryPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Azure Compute Gallery is publicly accessible');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});