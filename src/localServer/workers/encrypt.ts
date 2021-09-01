const encryptWorkerDoCommand = ( cmd: worker_command ) => {

    switch ( cmd.cmd ) {
        case 'encrypt_createPasscode': {
            if ( !cmd.data || cmd.data.length < 2) {
                cmd.err = 'INVALID_DATA'
                return returnCommand ( cmd )
            }
            delete cmd.err
            //          make password group
            systemInitialization = cmd.data [1]
            
            return createNumberPasscode ( cmd, ( err, _pass ) => {
                if ( err ) {
                    cmd.err = 'GENERATE_PASSCODE_ERROR'
                    return returnCommand (cmd)
                }
                pass = _pass
                return initSeguroData (cmd)
            })
            
        }

        case 'storage_StoreContainerData': {
            if ( !cmd?.data || !cmd.data?.length) {
                cmd.err = 'INVALID_DATA'
                return returnCommand (cmd)
            }
            systemInitialization = cmd.data[0]
            return encrypt_InitSeguroDataToPGP (cmd)
        }

        case 'encrypt_TestPasscord': {
            return encrypt_TestPasscord (cmd)
        }

        default: {
            cmd.err = 'INVALID_COMMAND'
            returnCommand (cmd)
            return console.log (`encryptWorkerDoCommand unknow command!`)
        }
    }
}

const initEncrypt = () => {
    const baseUrl = self.name + 'utilities/'
    self.importScripts ( baseUrl + 'Buffer.js' )
    self.importScripts ( baseUrl + 'openpgp.min.js' )
    self.importScripts ( baseUrl + 'UuidV4.js' )
    self.importScripts ( baseUrl + 'Pouchdb.js' )
    self.importScripts ( baseUrl + 'PouchdbFind.js' )
    self.importScripts ( baseUrl + 'PouchdbMemory.js' )
    self.importScripts ( baseUrl + 'scrypt.js' )
    self.importScripts ( baseUrl + 'async.js' )
    self.importScripts ( baseUrl + 'utilities.js' )
    self.importScripts ( baseUrl + 'generatePassword.js' )
    self.importScripts ( baseUrl + 'storage.js' )

    onmessage = e => {
        const jsonData = buffer.Buffer.from ( e.data ).toString()
		let cmd: worker_command
		try {
			cmd = JSON.parse ( jsonData )
		} catch ( ex ) {
			return console.dir ( ex )
		}
        if ( !workerReady ) {
            cmd.err = 'NOT_READY'
            return returnCommand ( cmd )
        }

        return encryptWorkerDoCommand ( cmd )
    }
    return checkStorage ()
}

let SeguroKeyChain: encrypt_keys_object | null = null
let systemInitialization: systemInitialization|null = null
let pass: passInit| null = null

const initSeguroData = ( cmd: worker_command ) => {
    
    const ret: encrypt_keys_object = {
        containerKeyPair: {
            publicKeyArmor: '',
            privateKeyArmor: '',
            keyOpenPGP_obj: {
                privateKeyObj: null,
                publicKeyObj: null
            }
        },
        keyChain: {
            deviceKeyPair: {
                publicKeyArmor: '',
                privateKeyArmor: '',
                keyOpenPGP_obj: {
                    privateKeyObj: null,
                    publicKeyObj: null
                }
            },
            seguroAccountKeyPair: {
                publicKeyArmor: '',
                privateKeyArmor: '',
                keyOpenPGP_obj: {
                    privateKeyObj: null,
                    publicKeyObj: null
                }
            },
            profiles: []
        },
        isReady: false,
        toStoreObj: null,
        encryptedString: ''
    }
    createKey( pass?.passcode || '', '', '')
    .then (( data: any ) => {
        ret.containerKeyPair = {
            publicKeyArmor: data.publicKey,
            privateKeyArmor: data.privateKey,
            keyOpenPGP_obj: null
        }
        return createKey ('', '', '')
    })
    .then (( data: any) => {
        ret.keyChain.deviceKeyPair.publicKeyArmor = data.publicKey
        ret.keyChain.deviceKeyPair.privateKeyArmor = data.privateKey
        return createKey ('', '','')
    })
    .then (( data: any ) => {
        ret.keyChain.seguroAccountKeyPair.publicKeyArmor = data.publicKey
        ret.keyChain.seguroAccountKeyPair.privateKeyArmor = data.privateKey
        return createKey ('', '','')
    })
    .then (( data: any ) => {
        const _key: keyPair = {
            publicKeyArmor: data.publicKey,
            privateKeyArmor: data.privateKey,
            keyID: '',
            keyOpenPGP_obj: null
        }
        ret.keyChain.profiles.push(_key)
        
        return async.waterfall ([
            ( next: any ) => createEncryptObject (ret, next ),
            (obj: any, next: any ) => {
                SeguroKeyChain = obj
                return initEncryptObject (cmd, next )
            }
        ], err => {
            if (err) {
                logger (`initEncryptObject ERROR`, err )
                cmd.err = 'OPENPGP_RUNNING_ERROR'
                return returnCommand (cmd)
            }

            return encrypt_InitSeguroDataToPGP (cmd)
        })
    })
    .catch (( ex: any ) => {
        cmd.err = 'OPENPGP_RUNNING_ERROR'
        cmd.data = []
        logger (`initSeguroData on ERROR`, ex)
        return returnCommand ( cmd )
    })
}

const createEncryptObject = ( obj: encrypt_keys_object, CallBack: ( err: Error|null, obj?: encrypt_keys_object ) => void ) => {
    if ( !obj ) {
        return CallBack ( new Error ('createEncryptObject Error! Have no obj') )
    }
    return openpgp.readKey ({ armoredKey: obj.keyChain.deviceKeyPair.publicKeyArmor})
    .then ((n: any) => {
        obj.keyChain.deviceKeyPair.keyOpenPGP_obj = {
            privateKeyObj: null,
            publicKeyObj: n
        }
        obj.keyChain.deviceKeyPair.keyID = n.getKeyIDs()[1].toHex ().toUpperCase ()
        return async.eachSeries ( obj.keyChain.profiles, ( n, next ) => {
            const obj = n.keyOpenPGP_obj = {
                privateKeyObj: null,
                publicKeyObj: null
            }
            openpgp.readKey ( { armoredKey: n.publicKeyArmor })
            .then ((nn:any) => {
                
                obj.publicKeyObj = nn
                
                n.keyID = nn.getKeyIDs()[1].toHex ().toUpperCase ()
                return openpgp.readPrivateKey ({ armoredKey: n.privateKeyArmor })
            }).then ((nn: any ) => {
                obj.privateKeyObj = nn
                return next ()
            }).catch ((ex: Error ) => {
                return next (ex)
            })
        }, err => {
            if ( err ) {
                return CallBack ( err )
            }
            return CallBack (null, obj)
        })
    }).catch ((ex: Error ) => {
        return CallBack ( ex )
    })
}

const initEncryptObject = (cmd: worker_command, CallBack: (err?: Error) => void ) => {
    if ( !SeguroKeyChain ||  !SeguroKeyChain.containerKeyPair || !pass ) {
        const err = `encrypt worker initEncryptObject Error: have no SeguroKeyChain!`
        logger ( err )
        return CallBack (new Error (err))
    }
    const _SeguroKeyChain = SeguroKeyChain
    const containerKey = _SeguroKeyChain.containerKeyPair
    const containerKey_obj = containerKey.keyOpenPGP_obj = {
        privateKeyObj: null,
        publicKeyObj: null
    }

    const makeKeyChainObj = () => {
        if ( !SeguroKeyChain ) {
            const err = `initEncryptObject makeKeyChainObj !SeguroKeyChain ERROR! `
            logger (err)
            return CallBack ( new Error (err))
        }
        const _SeguroKeyChain = SeguroKeyChain
        const deviceKey = _SeguroKeyChain.keyChain.deviceKeyPair
        const seguroKey = _SeguroKeyChain.keyChain.seguroAccountKeyPair
        const seguroKey_obj = seguroKey.keyOpenPGP_obj = {
            privateKeyObj: null,
            publicKeyObj: null
        }
        const deviceKey_obj = deviceKey.keyOpenPGP_obj = {
            privateKeyObj: null,
            publicKeyObj: null
        }

        _SeguroKeyChain.toStoreObj = () => {
            const kk: encrypt_keys_object = {
                containerKeyPair: {
                    privateKeyArmor: containerKey.privateKeyArmor,
                    publicKeyArmor: containerKey.publicKeyArmor,
                    keyOpenPGP_obj: null
                },
                keyChain: {
                    deviceKeyPair: {
                        publicKeyArmor: deviceKey.publicKeyArmor,
                        privateKeyArmor: deviceKey.privateKeyArmor,
                        keyOpenPGP_obj: null
                    },
                    seguroAccountKeyPair: {
                        publicKeyArmor: seguroKey.publicKeyArmor,
                        privateKeyArmor: seguroKey.privateKeyArmor,
                        keyOpenPGP_obj: null
                    },
                    profiles: []
                },
                isReady: false,
                toStoreObj: null,
                encryptedString: ''
            }
            _SeguroKeyChain.keyChain.profiles.forEach ( n => {
                const key = { publicKeyArmor: n.publicKeyArmor, privateKeyArmor: n.privateKeyArmor, keyID: n.keyID, keyOpenPGP_obj: null }
                kk.keyChain.profiles.push ( key )
            })
            return kk
        }

        openpgp.readKey ({ armoredKey: containerKey.publicKeyArmor })
        .then (( n: any ) => {
            containerKey_obj.publicKeyObj = n
            return openpgp.readPrivateKey ({ armoredKey: containerKey.privateKeyArmor })
        }).then ((n: any ) => openpgp.decryptKey ({ privateKey:n, passphrase: pass?.passcode }))
        .then ((n: any) => {
            containerKey_obj.privateKeyObj = n
            return openpgp.readPrivateKey ({ armoredKey: seguroKey.privateKeyArmor })
        }).then ((n: any ) => {
            seguroKey_obj.privateKeyObj = n
            return openpgp.readKey ({ armoredKey: seguroKey.publicKeyArmor })
        }).then ((n: any) => {
            seguroKey_obj.publicKeyObj = n
            return openpgp.readPrivateKey ({ armoredKey: deviceKey.privateKeyArmor })
        }).then ((n: any) => {
            deviceKey_obj.privateKeyObj = n
            return openpgp.readKey ({ armoredKey: deviceKey.publicKeyArmor })
        }).then ((n: any) => {
            deviceKey_obj.publicKeyObj = n
            _SeguroKeyChain.isReady = true
            
            if ( pass ) {
                pass.passcode = pass._passcode = pass.password = ''
            }
            return CallBack ()
        }).catch ((ex: Error) => {
            return CallBack (ex)
        })
    }

    const unlockContainerKeyPair = () => {
        
        openpgp.readPrivateKey ({ armoredKey: containerKey.privateKeyArmor })
        .then (( n: any ) => openpgp.decryptKey ({ privateKey:n, passphrase: pass?.passcode }))
        .then (( n: any ) => {
            containerKey_obj.privateKeyObj = n
            return openpgp.readKey ({ armoredKey: containerKey.publicKeyArmor })
        }).then ((n: any) => {
            containerKey_obj.publicKeyObj = n
            
            if ( !_SeguroKeyChain.keyChain.deviceKeyPair.publicKeyArmor ) {
                
                async.waterfall ([
                    ( next: any ) => {
                        if ( !SeguroKeyChain?.encryptedString ) {
                            const err = 'SeguroKeyChain locked but have no SeguroKeyChain.encryptedString ERROR!'
                            logger ( err )
                            return next (new Error (err))
                        }
                        return decryptWithContainerKey ( SeguroKeyChain.encryptedString, next )
                    },
                    ( data: string, next: any ) => {
                        let sysInit = null
                        const _data = buffer.Buffer.from (data,'base64').toString()
                        try {
                            sysInit = JSON.parse (_data)
                        } catch ( ex ) {
                            const err = 'unlockContainerKeyPair decryptWithContainerKey JSON.parse Error'
                            next (new Error (err))
                            return logger ( err)
                        }
                        
                        const _SeguroKeyChain:encrypt_keys_object  = sysInit.SeguroKeyChain
                        
                        return createEncryptObject (_SeguroKeyChain, next )
                    }
                ], ( err, obj: any ) => {
                    if ( err ) {
                        cmd.err = 'OPENPGP_RUNNING_ERROR'
                        return returnCommand (cmd)
                    }
                    SeguroKeyChain = obj
                    return makeKeyChainObj ()
                    
                })
            }
            return makeKeyChainObj ()
        })
        .catch ((ex: Error) => {
            return CallBack ( ex )
        })
    }

    if ( !pass.passcode ) {
        return decodePasscode (cmd, (err) => {
            return unlockContainerKeyPair ()
        })
    }
    return unlockContainerKeyPair ()
}

const createKey = ( passwd: string, name: string, email: string ) => {
	const userId = {
		name: name,
		email: email
	}
	const option = {
        type: 'ecc',
		passphrase: passwd,
		userIDs: [ userId ],
		curve: 'curve25519',
        format: 'armored'
	}

	return openpgp.generateKey ( option )
}

const encrypt_TestPasscord = (cmd: worker_command) => {
    if ( !cmd.data?.length || !pass ) {
        cmd.err = 'INVALID_DATA'
        return returnCommand (cmd)
    }
    
    pass.password = cmd.data[0]
    return initEncryptObject (cmd, ( err )=> {
        if ( err ) {
            cmd.err = 'FAILURE'
            return returnCommand ( cmd )
        }

        return storage_StoreContainerData (cmd)
    })
}

const encryptWithContainerKey = async ( text: string, CallBack: ( err: Error|null, encryptedText?: string ) => void ) => {
    if ( !SeguroKeyChain?.isReady ) {
        logger ('!SeguroKeyChain?.isReady waiting!')
        setTimeout (() => {
            return encryptWithContainerKey (text, CallBack )
        }, 1000)
        return
    }
    logger ('encryptWithContainerKey start!')
    const encryptObj = {
        message: await openpgp.createMessage({ text: buffer.Buffer.from (text).toString('base64') }),
        encryptionKeys: SeguroKeyChain?.containerKeyPair?.keyOpenPGP_obj?.publicKeyObj,
        signingKeys: SeguroKeyChain?.containerKeyPair?.keyOpenPGP_obj?.privateKeyObj
    }

    return openpgp.encrypt(encryptObj).then (( encrypted: string ) => {
        return CallBack ( null, encrypted )
    }).catch ((ex: Error) => {
        return CallBack ( ex )
    })

}

const encrypt_InitSeguroDataToPGP = ( cmd: worker_command ) => {

    if ( !SeguroKeyChain || !SeguroKeyChain.isReady || !systemInitialization ) {
        logger (`encrypt.js encrypt_InitSeguroDataToPGP error: !SeguroKeyChain?.toStoreObj || !systemInitialization`, cmd )
        cmd.err = 'INVALID_DATA'
        return returnCommand(cmd)
    }
    
    const encryptObj = {
        SeguroKeyChain: SeguroKeyChain.toStoreObj(),
        Preferences: systemInitialization
    }
    
    return encryptWithContainerKey(JSON.stringify (encryptObj), (err, encryptedText) => {
        if ( err ) {
            logger(`encrypt.js encryptWithContainerKey OpenPGP error`, err)
            cmd.err = 'OPENPGP_RUNNING_ERROR'
            return returnCommand(cmd)
        }
        if ( encryptedText && SeguroKeyChain) {
            SeguroKeyChain.encryptedString = encryptedText
        }
        
        return returnSeguroInitializationData (cmd)
    })

}

const decryptWithContainerKey = ( encryptedMessage: string, CallBack: (err: Error|null, text?: string) => void) => {
    let ret = ''
    openpgp.readMessage({armoredMessage: encryptedMessage})
    .then ((message: any) => openpgp.decrypt({
        message,
        verificationKeys: SeguroKeyChain?.containerKeyPair?.keyOpenPGP_obj?.publicKeyObj,
        decryptionKeys: SeguroKeyChain?.containerKeyPair?.keyOpenPGP_obj?.privateKeyObj
    }))
    .then ((n: any) => {
        ret = n.data
        return n.verified
    })
    .then ((verified: boolean ) => {
        return CallBack (null, ret )
    })
    .catch (( ex: Error ) => {
        return CallBack ( ex )
    })
}

initEncrypt ()
