'use strict';

const when = require('when');
const async = require('async');
const ntlm = require('httpntlm').ntlm;
const httpreq = require('httpreq');
const https = require('https');
const http = require('http');
const _ = require('lodash');

const fs = require('fs');

const agent = new http.Agent(
  { keepAlive: true
    , maxSockets: 5
    , keepAliveMsecs: 30000
  }
);

const agentS = new https.Agent(
  { keepAlive: true
    , maxSockets: 5
    , keepAliveMsecs: 30000
  }
);

const NtlmSecurity = require('./ntlm/ntlmSecurity');
const HttpClient = require('./ntlm/http');

const getUrl1 = function(url, filePath, config, options) {
  let ntlmOptions = {
    username: config.username,
    password: config.password
  };

  ntlmOptions = _.merge(ntlmOptions, _.clone(options));
  ntlmOptions.url = url;

  return when.promise((resolve, reject) => {
    ntlm.get(ntlmOptions, function(err, res) {
      if(err) reject(err);
      else if(res.statusCode == 401) reject(new Error('NTLM StatusCode 401: Unauthorized.'));
      else fs.writeFile(filePath, res.body, function(err) {
        if(err) reject(err);
        else resolve(filePath);
      });
    });
  });
}

const isHttps = (str) => str && str.substring(0, 5) === 'https';

const getUrl2 = function(url, filePath, config, options) {
  let ntlmOptions = {
    username: config.username,
    password: config.password,
    domain: '',
    workstation: ''
  };

  ntlmOptions = _.merge(ntlmOptions, _.clone(options));
  ntlmOptions.url = url;

  return when.promise((resolve, reject) => {
    async.waterfall([
      function (callback){
        var type1msg = ntlm.createType1Message(ntlmOptions);
        httpreq.get(ntlmOptions.url, {
            headers:{
              'Connection' : 'keep-alive',
              'Authorization': type1msg,
              'X-CL-DEBUG': options.hashedPassword
            },
          agent: isHttps(ntlmOptions.url) ? agentS : agent
        }, callback);
      },

      function (res, callback) {
        if (!res.headers['www-authenticate'])
          return callback(new Error('www-authenticate not found on response of second request'));

        var type2msg = ntlm.parseType2Message(res.headers['www-authenticate']);
        var type3msg = ntlm.createType3Message(type2msg, ntlmOptions);
        setImmediate( function() {
          httpreq.get(ntlmOptions.url, {
            headers:{
              'Connection' : 'Close',
              'Authorization': type3msg,
              'X-CL-DEBUG': options.hashedPassword
            },
            allowRedirects: false,
            agent: isHttps(ntlmOptions.url) ? agentS : agent
          }, callback);
        });
      }
    ], function (err, res) {
      if(err) reject(err);
      else if(res.statusCode == 401) reject(new Error('NTLM StatusCode 401: Unauthorized.'));
      else fs.writeFile(filePath, res.body, function(err) {
        if(err) reject(err);
        else resolve(filePath);
      });
    });
  });

}

// define ntlm auth
const NTLMAuth = function(config, options) {
  if(typeof config === 'object'
    && _.has(config, 'host')
    && _.has(config, 'username')
    && _.has(config, 'password')
  ) {
    return {
      wsdlOptions: { httpClient: HttpClient },
      authProfile: new NtlmSecurity(config.username, config.password, options),
      getUrl: function(url, filePath) { return getUrl2(url,filePath,config,options);}
    };
  } else {
    throw new Error('missing required config parameters');
  }
};

module.exports = NTLMAuth;
