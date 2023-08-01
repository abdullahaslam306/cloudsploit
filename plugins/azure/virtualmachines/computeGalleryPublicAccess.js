var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Azure Compute Gallery Public Access',
    category: 'Virtual Machines',
    domain: 'Compute',
    description: 'Ensures that the Azure Compute Gallery is not publicly accessible.',
    more_info: 'Making the Azure Compute Gallery publicly accessible may lead to unauthorized access and potential security risks.',
    recommended_action: 'Modify Compute Gallery and allow RBAC (Roles-based Access Control)only',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-machines/azure-compute-gallery#sharing',
    apis: ['computeGallery:listAll'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.computeGallery, function(location, rcb) {

            var galleries = helpers.addSource(cache, source, ['computeGallery', 'listAll', location]);

            if (!galleries) return rcb();

            if (galleries.err || !galleries.data) {
                helpers.addResult(results, 3, 'Unable to query for Azure Compute Galleries: ' + helpers.addError(galleries), location);
                return rcb();
            }

            if (!galleries.data.length) {
                helpers.addResult(results, 0, 'No Azure Compute Galleries found', location);
                return rcb();
            }

            for (let gallery of galleries.data) {
                if (!gallery.id) continue;

                if (gallery.properties && gallery.properties.sharingProfile && gallery.properties.sharingProfile.permissions.toLowerCase() === 'private') {
                    helpers.addResult(results, 0, 'Azure Compute Gallery is not publicly accessible', location, gallery.id);
                } else {
                    helpers.addResult(results, 2, 'Azure Compute Gallery is publicly accessible', location, gallery.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
