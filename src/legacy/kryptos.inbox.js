/* global KRYPTOS, Handlebars, showErrorMessage, Layout, Metronic, URL, ComponentsjQueryUISliders, Sanitize, decodeURIComponent, CommonDashboard, Contacts, Groups, App */
"use strict";
/**
 * KRYPTOS is a cryptographic library wrapping and implementing the
 * Web Cryptography API. It supports both symmetric keys and asymmetric key pair
 * generation, encryption, decryption, signing and verification.
 *
 * If the Web Cryptography API is not supported by the browser, it falls back
 * to the an implementation of the MSR JavaScript Cryptography Library.
 *
 *
 * @name KRYPTOS
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2018.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 4.0
 */

/**
 * The KRYPTOS Inbox module.
 */
KRYPTOS.Inbox = function () {

    let keyStore = null;
    let hasInit = false;

     let getInbox = function (json, callback, errorHandler) {
        App.KA.getInbox(json, function(data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let getSent = function (json, callback, errorHandler) {
        App.KA.getSent(json, function(data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let getDrafts = function (json, callback, errorHandler) {
        App.KA.getDrafts(json, function(data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let getStarred = function (json, callback, errorHandler) {
        App.KA.getStarred(json, function(data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let getTrashed = function (json, callback, errorHandler) {
        App.KA.getTrashed(json, function(data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let draftMail = function(recipients, subject, plainText, attachments, uuid, callback, errorCallback) {

        encryptMail(recipients, subject, plainText, attachments, function(result) {

            for (let i = 0; i < result.keys.length; i++) {
                result.keys[i].u = Contacts.getUsername(result.keys[i].u);
            }

            let sendData = {
                recipients: JSON.stringify(recipients),
                message: result.blob,
                keys: JSON.stringify(result.keys)
            };

            if (uuid) {
                sendData['uuid'] = uuid;
            }

            if (!KRYPTOS.utils.isEmpty(attachments)) {
                for (let i = 0; i < attachments.length; i++) {
                    sendData['attachment_' + attachments[i].uuid] = attachments[i].uuid;
                }
            }

            App.KA.draftMail(sendData, callback, errorCallback);

        }, function(error) {
            errorCallback(error);
        });


    };

    let checkMail = function (callback, errorHandler) {
        App.KA.checkMail(function (data) {
            callback(data);
        }, errorHandler)
    };

    let searchMail = function (type, paginator, advSearch, callback, errorHandler) {
        let advSearchParams = "";
        let params = paginator ? "?" + $.param(paginator) : '';
        if (advSearch) {
            if (typeof advSearch === 'string' || advSearch instanceof String) {
                advSearchParams = advSearch;
            } else {
                advSearchParams = $.param(advSearch);
            }
            params += "&" + advSearchParams;
        } else {
            advSearchParams = null;
        }
        App.KA.searchMail({type: type, params: params},function (data) {
            getMessages(data, callback);
        }, errorHandler);
    };

    let sendAutoMail = function(subject, emails, recipients, content) {
        keyStore.getRecipientsPublicKeys(emails, function(success, message) {

            if (!success) {

                showErrorMessage("Email Not Sent!", message);
            } else {
                let plainText = {
                    timestamp: new Date().getTime(),
                    subject: encodeURIComponent(subject),
                    to: "",//KU.u2e(KU.escapeHTML(to)),
                    body: encodeURIComponent(content),
                    attachments: []
                };

                let Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, recipients, function(success, error) {
                    if (success) {

                    }
                    else {
                        KU.error(showErrorMessage, 'Email Not Sent!', error);
                    }
                });

                Encrypter.encrypt('message', []);
            }

        });
    };

    let getMessages = function(data, callback) {

        let usePDK = false;
        if (data.mails) {
            let promises = [];
            for (let i = 0; i < data.mails.length; i++) {
                if (data.mails[i].type === 'mail') {
                    usePDK = true;
                    break;
                }
            }
            if (usePDK) {
                for (let i = 0; i < data.mails.length; i++) {
                    // Store userId to username and username to userId maps (before storing public keys)
                    if (data.mails[i].recipients && data.mails[i].recipients.map) {
                        for (let r of data.mails[i].recipients.map) {
                            Contacts.setUserId(r.username, r.id);
                            Contacts.setUsernameId(r.id, r.username);
                        }
                    }
                }
                // Store public keys
                if (data.public_keys) {
                    for (let i = 0; i < data.public_keys.length; i++) {
                        keyStore.setPublicKeys(Contacts.getUserId(data.public_keys[i].username), data.public_keys[i].public_keys);
                    }
                }
                for (let i = 0; i < data.mails.length; i++) {
                    if (data.mails[i].type === 'mail') {
                        
                        data.mails[i].e2e = true;

                        let mail = data.mails[i];
                        let message = App.KU.b642ab(mail.mail);

                        //let pvk = KRYPTOS.Keys.getPublicKey(data.mails[i].username, 'verify');
//                        keyStore.getPublicKey(mail.username, 'verify', function(pvk) {
                            App.KU.extractMessage(message, function(encryptedKey, iv, cipherText, signature) {
                                promises.push(new KRYPTOS.Decrypter(keyStore, encryptedKey, iv, cipherText, signature, null, null, callback).decrypt2(Contacts.getUserId(mail.username), mail.uuid));
                            });
//                        });
                    }
                    else { // system
                        data.mails[i].e2e = true;
                        data.mails[i].subject_f = data.mails[i].subject;
                        data.mails[i].body = data.mails[i].mail;
                        //data.mails[i].body_preview = $(data.mails[i].mail).text();
                        data.mails[i].display_name = data.mails[i].from;
                        data.mails[i].display_name_f = App.KU.formatLine(
                            App.KU.extractDisplayNameFromFullName(data.mails[i].from), 40);
                    }
                    //KRYPTOS.session.setItem("m" + data.mails[i].uuid, JSON.stringify(data.mails[i]));
                }
                
                KRYPTOS.Promise.all(promises)
                    .then(function(result) {
                        for (let i = 0; i < data.mails.length; i++) {
                            for (let j = 0; j < result.length; j++) {
                                if (result[j].uuid === data.mails[i].uuid) {
                                    if(result[j].plain.text) {
                                        data.mails[i].text = result[j].plain.text;
                                    }
                                    data.mails[i].body = result[j].plain.body;
                                    data.mails[i].attachments_meta = result[j].plain.attachments;
                                    if (result[j].plain.subject === '') {
                                        data.mails[i].subject = '(no subject)';
                                        data.mails[i].subject_f = '(no subject)';
                                    }
                                    else {
//                                            data.mails[i].subject = decodeURIComponent(result[j].plain.subject);
                                        data.mails[i].subject = App.KU.decodeURIComp(data.sanitizer, result[j].plain.subject, 'subj');
                                        data.mails[i].subject_f = App.KU.formatSubject(data.sanitizer, result[j].plain.subject, 'subj');
                                    }

                                    let sanitized = "";
                                    let isSystem = data.mails[i].type === 'system' || data.mails[i].type === 'notification';

                                    if (isSystem) {
                                        sanitized = data.mails[i].body;
                                    }
                                    else {
                                        sanitized = App.KU.sanitize(App.getSanitizer(), App.KU.dURI(data.mails[i].body), true);
                                    }


                                    data.mails[i].body_sanitized = sanitized;
                                    let chtml = $.parseHTML(sanitized);
                                    data.mails[i].body_preview = $(chtml).text();

                                    if (result[j].plain.reply_to) {
                                        data.mails[i].reply_to = result[j].plain.reply_to;
                                    }

                                    if(result[j].plain.forward_to) {
                                        data.mails[i].forward_to = result[j].plain.forward_to;
                                    }

                                    let fromDN = App.KU.extractDisplayNameFromFullName(data.mails[i].from);

                                    if (!fromDN) {
                                        data.mails[i].display_name = data.mails[i].from;
                                        data.mails[i].display_name_f = App.KU.formatLine(data.mails[i].from, 40);
                                    } else {
                                        data.mails[i].display_name = fromDN;
                                        data.mails[i].display_name_f = App.KU.formatLine(fromDN, 40);
                                    }

                                    if (data.mails[i].recipients && data.mails[i].recipients.first) {
                                        let toDN = App.KU.extractDisplayNameFromFullName(data.mails[i].recipients.first);
                                        data.mails[i].recipients.display_name = toDN;
                                        //data.mails[i].recipients.display_name_f = KU.formatLine(toDN, 40);
                                        data.mails[i].recipients.display_name_f = "";
                                        let allrecipients = data.mails[i].recipients.all.split(',');
                                        for (let ii=0; ii < allrecipients.length; ii++ ){
                                            toDN = App.KU.extractDisplayNameFromFullName(allrecipients[ii]).trim();
                                            data.mails[i].recipients.display_name_f += toDN + ', ';
                                        }
                                        data.mails[i].recipients.display_name_f =
                                            data.mails[i].recipients.display_name_f.substr(0, data.mails[i].recipients.display_name_f.length -2);
                                        data.mails[i].recipients.display_name_f = App.KU.formatLine(data.mails[i].recipients.display_name_f, 35);
                                    }
                                    
//                                    for (let r of data.mails[i].recipients.map) {
//                                        Contacts.setUserId(r.username, r.id);
//                                        Contacts.setUsernameId(r.id, r.username);
//                                    }

                                    data.mails[i].failed = result[j].failed;
                                    break;
                                }
                            }
                        }
                        callback(true, data);
                    }).catch(function(error) {
                        App.KU.log(error);
                        callback(false, error);
                    });
            }
            else { // system only
                for (let i = 0; i < data.mails.length; i++) {
                    data.mails[i].e2e = true;
//                    data.mails[i].from_f = KU.formatLine(data.mails[i].from, 50);
                    data.mails[i].display_name = data.mails[i].from;
                    data.mails[i].display_name_f = data.mails[i].from;
                    data.mails[i].subject_f = data.mails[i].subject;
                    data.mails[i].body = data.mails[i].mail;
                    //data.mails[i].body_preview = $(data.mails[i].mail).text();
                }
                callback(true, data);
            }
        }
        else {
            callback(true, false);
        }
    };

    let encryptFile = function(file, callback) {
        KRYPTOS.Files.encryptFile(file, callback);
    };

    let decryptFile = function(meta, data, callback) {
        KRYPTOS.Files.decryptFile(meta, data, callback);
    };

    let uploadAttachment = function(file, callback, uploadHandler) {
        encryptFile(file, function(success, encryptedFile, meta) {
            if (!success) {
                KRYPTOS.utils.error(showErrorMessage, "File upload error", encryptedFile);
                return;
            }
            let sendData = {
                attachment: encryptedFile
            };

            App.KA.uploadAttachment(sendData, function(uploadResponse) {
                meta.uuid = uploadResponse.uuid;
                callback(meta);
            }, function(r2) {
            }, uploadHandler);

        });
    };

    let downloadAttachment = function(messageId, meta, callback, downloadHandler) {
        return App.KA.downloadAttachment(messageId, meta.uuid, function(downloadResponse) {
            console.log('DOWNLOAD COMPLETE!!!!!!!!!!!!!!!!');
            decryptFile(meta, downloadResponse, function(success, blob) {
                if (!success) {
                    KRYPTOS.utils.error(showErrorMessage, "File download error", blob);
                    return;
                }
                callback(blob);
            });

        }, downloadHandler);
    };

    let formatUuids = function(mails) {
        return mails.map(function(mail) {
                return mail.recipient_type + ":" + mail.uuid;
            }).join(',');
    };

    let readMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.readMail({message_id: uuids}, callback, errorCallback);
    };

    let unreadMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.unreadMail({message_id: uuids}, callback, errorCallback);
    };

    let starMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.starMail({message_id: uuids}, callback, errorCallback);
    };

    let unstarMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.unstarMail({message_id: uuids}, callback, errorCallback);
    };

    let trashMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.trashMail({message_id: uuids}, callback, errorCallback);
    };

    let restoreMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.restoreMail({message_id: uuids}, callback, errorCallback);
    };

    let deleteMail = function (mails, callback, errorCallback) {
        let uuids = formatUuids(mails);
        App.KA.deleteMail({message_id: uuids}, callback, errorCallback);
    };

    let encryptMail = function(usernames, subject, body, attachments, callback, errorCallback) {
        let usernameList = usernames.from;
        let userIds = [];
        if (usernames.to) {
            usernameList = usernameList.concat(usernames.to);
        }
        if (usernames.cc) {
            usernameList = usernameList.concat(usernames.cc);
        }
        if (usernames.bcc) {
            usernameList = usernameList.concat(usernames.bcc);
        }
        for (let i = 0; i < usernameList.length; i++) {
            userIds.push(Contacts.getUserId(usernameList[i]));
        }


        let attachmentsFormatted = [];
        for (let i = 0; i < attachments.length; i++) {
            attachmentsFormatted.push(App.KU.attachment(attachments[i]));
        }

        KRYPTOS.Contacts.getServicePublicKeys(userIds, "mail", function(success, message) {
            if (!success) {
                errorCallback(false, message.errors.username);
            }
            else {
                let plainText = {
                    timestamp: new Date().getTime(),
                    subject: App.KU.encodeURI(subject),
                    body: App.KU.encodeURI(body),
                    attachments: attachmentsFormatted
                };
                let Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, {to: userIds}, function(success, result) {
                    if (success) {

                        callback(result);

                    }
                    else {
                        errorCallback(result);
                    }
                });

//                if(uuid) {
//                    sendData['uuid'] = uuid;
//                }
//
//                if ($form.find('input[name="message_id"]').attr('data-reply')) {
//                    sendData['reply'] = $form.find('input[name="message_id"]').attr('data-reply-id');
//                }
//
//                if ($form.find('input[name="message_id"]').attr('data-forward')) {
//                    sendData['forward'] = $form.find('input[name="message_id"]').attr('data-forward-id');
//                }


                Encrypter.encrypt();
            }

        }, errorCallback);
    };
    let sendMail = function(recipients, subject, plainText, attachments, uuid, callback, errorCallback) {


        encryptMail(recipients, subject, plainText, attachments, function(result) {

            for (let i = 0; i < result.keys.length; i++) {
                result.keys[i].u = Contacts.getUsername(result.keys[i].u);
            }

            let sendData = {
                recipients: JSON.stringify(recipients),
                message: result.blob,
                keys: JSON.stringify(result.keys)
            };

            if (uuid) {
                sendData['uuid'] = uuid;
            }

            if (!KRYPTOS.utils.isEmpty(attachments)) {
                for (let i = 0; i < attachments.length; i++) {
                    sendData['attachment_' + attachments[i].uuid] = attachments[i].uuid;
                }
            }

            App.KA.sendMail(sendData, callback, errorCallback);

        }, function(error) {
            errorCallback(error);
        });


    };

    let init = function(mailKeyStore) {
        keyStore = mailKeyStore;
        if (!hasInit) {
            hasInit = true;
        }
    };

    return {

        sendMail: sendMail,

        checkMail: checkMail,

        searchMail: searchMail,

        sendAutoMail: sendAutoMail,

        getInbox: getInbox,
        getSent: getSent,
        getDrafts: getDrafts,
        getStarred: getStarred,
        getTrashed: getTrashed,

        uploadAttachment: uploadAttachment,
        downloadAttachment: downloadAttachment,

        readMail: readMail,
        unreadMail: unreadMail,
        starMail: starMail,
        unstarMail: unstarMail,
        trashMail: trashMail,
        restoreMail: restoreMail,
        deleteMail: deleteMail,
        draftMail: draftMail,

        init: init

    };

}();
