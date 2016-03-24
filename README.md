# Cordova / PhoneGap iOS TouchID Plugin
iOS TouchID plugin for Cordova / PhoneGap.

## AngularJS / Ionic
### Verify if TouchID is available

function touchIsAvailable(){
  //Set the Defer
	defer = $q.defer();
  // Check if touchid is available
  $window.plugins.touchid.isAvailable( function( success ){
    defer.resolve( success );
  }, function( error ){
    defer.reject( error );
  });
  // Return the Promise
	return defer.promise;
}

### Verify a fingerprint
- label - STRING
- fingerprintonly - 1 or 0 (1 to use only fingerprint, 0 to also allow the user to enter a passcode as failover)

function verifyFingerprint( fingerprintonly ){
  //Set the Defer
	defer = $q.defer();
  $window.plugins.touchid.verifyFingerprint( label, fingerprintonly, null, function( success ){
    defer.resolve( success );
  }, function( error  ){
    defer.reject( error );
  });
  // Return the Promise
	return defer.promise;
}
