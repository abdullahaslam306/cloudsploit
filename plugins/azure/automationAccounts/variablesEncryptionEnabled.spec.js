var expect = require('chai').expect;
var variablesEncryptionEnabled = require('./variablesEncryptionEnabled');

const automationAccounts = [
     {
      "id": "/subscriptions/subid/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/myaccount",
      "location": "eastus2",
      "name": "myaccount",
      "type": "Microsoft.Automation/AutomationAccounts",
      "properties": {
        "creationTime": "2016-09-24T00:47:04.227+00:00",
        "lastModifiedTime": "2017-02-09T21:35:16.4+00:00",
        "lastModifiedBy": "myEmailId@microsoft.com",
        "state": "Ok"
      }
     }
];

const variables = [
   {
      "id": "/subscriptions/subid/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/sampleAccount9/variables/sampleVariable",
      "name": "sampleVariable",
      "type": "Microsoft.Automation/AutomationAccounts/Variables",
      "isEncrypted": true,
      "description": "test"
    },
    {
      "id": "/subscriptions/subid/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/sampleAccount9/variables/sampleVariable",
      "name": "sampleVariable",
      "type": "Microsoft.Automation/AutomationAccounts/Variables",
      "isEncrypted": false,
       "description": "test"
    
    },

];

const createCache = (accounts, variables) => {
    const id = (accounts && accounts.length) ? accounts[0].id : null;
    return {
        automationAccount: {
            list: {
                'eastus': {
                    data: accounts
                }
            }
        },
        variables: {
            listByAutomationAccount: {
                'eastus': {
                    [id]: {
                        data: variables
                    }
                }
            }
        }
    }
};

describe('variablesEncryptionEnabled', function() {
    describe('run', function() {
        it('should give passing result if No existing automation account found found', function(done) {
            const cache = createCache([], []);
            variablesEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if variables are encrypted', function(done) {
            const cache = createCache([automationAccounts[0]], [variables[0]]);
            variablesEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account variable is encrypted');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for accounts', function(done) {
            const cache = createCache(null)
            variablesEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for automation accounts');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for variables', function(done) {
            const cache = createCache([automationAccounts[0]], null)
            variablesEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for automation account\'s variables:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if variables are not encrypted', function(done) {
            const cache = createCache([automationAccounts[0]], [variables[1]]);
            variablesEncryptionEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account variable is not encrypted');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 