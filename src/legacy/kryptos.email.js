/* global KRYPTOS, Handlebars, showErrorMessage, Layout, Metronic, URL, ComponentsjQueryUISliders, Sanitize, decodeURIComponent, CommonDashboard, Contacts, Groups */
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
 * @copyright Copyright © FortKnoxster Ltd. 2014 - 2017.
 * @license Apache License, Version 2.0 http://www.apache.org/licenses/LICENSE-2.0
 * @author MJ <mj@fortknoxster.com>
 * @version 3.1
 */

/**
 * The KRYPTOS ChatCall module.
 */
KRYPTOS.Email = function () {
    var KU = KRYPTOS.utils;
    var userId = KRYPTOS.session.getItem('id');
    var keyStore = null;
    var hasInit = false;
    var section = $('#email-container');
    var CD = null;
    var contentContainer = $('#email-container');
    var storageContainer = $('#storage-content');
    var content = $('#email-container .inbox-content');
    var storage = $('.storage-content');
    var loading = $('.inbox-loading');
    var listListing = '';
    var sound = null;
    var templateInbox = Handlebars.templates['inbox'];
    var templateCompose = Handlebars.templates['compose'];
    var templateSent = Handlebars.templates['sent'];
    var templateDrafts = Handlebars.templates['drafts'];
    var templateStarred = Handlebars.templates['starred'];
    var templateTrash = Handlebars.templates['trash'];
    var templateViewMail = Handlebars.templates['view-mail'];
    var templateAttachmentsUpload = Handlebars.templates['attachments-upload'];
    var templateAttachmentsDownload = Handlebars.templates['attachments-download'];
    var templateContactsGroups = Handlebars.templates['contacts-groups'];
    var templateContactsGroupsContacts = Handlebars.templates['contacts-groups-contacts'];
    var sanitizer = new Sanitize(Sanitize.Config.MAIL);
    var emailList = new Array();
    var recipientsSecure = true;
    var editor = null;

    var currentPage = 1;
    var currentType = 'inbox';
    //var currentRecipient = '';
    var advSearchParams = '';
    var pageType = '';
    var whereAreWe = '';    // Inbox|Compose|Reply|ReplyAll|Forward|Sent|Draft|Compose-Draft|Starred|Business|Spam
    var chatEnabled = true;

    var userSettings = null;
    var dragSourceElement = null;

    var quickSearch = null;

    Handlebars.registerHelper('select', function( value, options ){
        var $el = $('<select />').html( options.fn(this) );
        $el.find('[value="' + value + '"]').attr({'selected':'selected'});
        return $el.html();
    });

    // sound disabled
    var loadSound = function() {
//        sound = document.createElement('audio');
//        sound.setAttribute('src', '/sounds/Electronic_Chime.mp3');
    };

    // sound disabled
    var playSound = function() {
//        sound.play();
    };

    var initDatePickers = function() {
        $('#adv-search-dateFrom').datepicker({
            format: 'yyyy-mm-dd',
            endDate: '0d',
            autoclose: 'true',
            todayHighlight: true
        });

        $('#adv-search-dateUntil').datepicker({
            format: 'yyyy-mm-dd',
            endDate: '0d',
            autoclose: 'true',
            todayHighlight: true,

        });
    };

    var clearDatePickersAndCheckBoxes = function() {
        var advForm = $('#advance-search-form');
        advForm[0].reset();
        advForm.find('#adv-search-isUnread').prop('checked', false);
        advForm.find('#adv-search-hasAttachements').prop('checked', false);
        advForm.find('#adv-search-isStarred').prop('checked', false);
        advForm.find('#adv-search-dateFrom').datepicker('setDate', null);
        advForm.find('#adv-search-dateUntil').datepicker('setDate', null);
    };

    var checkDraft = function(callback) {
        var $saveDraftButon = $('.inbox-content button.save-draft');
        if ($saveDraftButon.length > 0) {
            if ($saveDraftButon.is(':disabled') || !$saveDraftButon.is(':visible')) { // Save already in progress (manual click or other)
                callback();
                return;
            }
            saveDraft(callback, false);
        }
        else {
            callback();
        }
    };

    var loadInbox = function(el, type, page, advSearch, skipNotification, callback) {

        CD.setActive(0);
        $(".Metronic-alerts").remove();
        CD.mailCheck(skipNotification);
        CD.overlayShow();
        var title = $('#email-container .inbox-nav > li.' + type + ' a').attr('data-title');
        var params = page ? "?" + $.param({
            page: page
        }) : '';

        CommonDashboard.setCurrentPage("email");

        //var advSearchParams = '';
        if (advSearch) {
            if (typeof advSearch === 'string' || advSearch instanceof String) {
                advSearchParams = advSearch;
            }
            else {
                advSearchParams = $.param(advSearch);
            }
            params += "&" + advSearchParams;
        }
        else {
            advSearchParams = null;
            //params = '';
            quickSearch.val('');
        }

        listListing = type;
        loading.show();
        clearContent(function() {
            toggleButton(el);
            menuTop('inbox-menu-item');
            //showMenu('mail');
            showSection(type);
            currentType = type;
            currentPage = page;
            if (type === 'sent') {
                //$('.mail-search-form input[name=recipient]').prop('placeholder', 'Search by receiver');
                if (advSearch && advSearch.searchtype === 'advance') {
                    quickSearch.val('');
                    quickSearch.prop('placeholder', 'Advanced search active ...');
                    quickSearch.prop('data-type', 'advanced');
                } else {
                    quickSearch.prop('placeholder', 'Search by receiver');
                    quickSearch.prop('data-type', 'basic');
                    //advSearchParams = null;
                    //advSearch = null;
                }
                $('.mail-search-form').show();
                $('#adv-search-Text').prop('placeholder', 'receiver');
                $('#adv-search-Text-Label').prop('textContent', 'Receiver: ');
                $('#adv-search-isUnread').parent().hide();
                $('#adv-search-isStarred').parent().hide();
                //$('#adv-search-hasAttachements').parent().css("margin-left", "0px");
            }
            else if (type === 'inbox' || type === 'starred') {

                if (advSearch && advSearch.searchtype === 'advance') {
                    quickSearch.val('');
                    quickSearch.prop('placeholder', 'Advanced search active ...');
                    quickSearch.prop('data-type', 'advanced');
                } else {
                    quickSearch.prop('placeholder', 'Search by sender');
                    quickSearch.prop('data-type', 'basic');
                    //advSearchParams = null;
                    //advSearch = null;
                }
                $('.mail-search-form').show();
                $('#adv-search-Text').prop('placeholder', 'sender');
                $('#adv-search-Text-Label').prop('textContent', 'Sender: ');
                $('#adv-search-isUnread').parent().show();

                $('#adv-search-isStarred').parent().show();
                //$('#adv-search-hasAttachements').parent().css("margin-left", "55px");
            } else {
                $('.mail-search-form').hide();
            }
            $('.dropdown').removeClass('open');

            $.ajax({
                type: "GET",
                cache: false,
                url: 'mail/' + type + params,
                dataType: "json",
                success: function (data) {
                    toggleButton(el);
                    leftMenu(type);
                    $('.inbox-header > h2').text(title).show();

                    data.sanitizer = sanitizer;
                    getMessages(data, function(success, mails) {
                        if (!success) {
                            if (callback) {
                                return callback(true, mails);
                            }
                            showErrorMessage("Unexpected Error", mails);
                            loading.hide();
                            return;
                        }
                        if (callback) {
                            return callback(true, mails);
                        }
                        var html = "";
                        if ((!mails && (page <= 1 || !page))) {
                            html = "<p>Sorry - there are no emails here.</p>";
                        }
                        else if (!mails && page > 0) {
                            // Mails deleted, reload inbox with previous page
                            loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, page - 1, advSearchParams);
                        }
                        else {
                            //mails.recipient = currentRecipient;
                            mails.recipient = advSearchParams;
                            switch (type) {
                                case 'inbox': html = templateInbox(mails); whereAreWe = 'inbox'; break;
                                case 'sent': html = templateSent(mails); whereAreWe = 'sent'; break;
                                case 'drafts': html = templateDrafts(mails); whereAreWe = 'drafts'; break;
                                case 'starred': html = templateStarred(mails); whereAreWe = 'starred'; break;
                                case 'trash': html = templateTrash(mails); whereAreWe = 'trash'; break;
                            }

                            if(advSearch) {
                                if(advSearch.isUnread) {
                                    whereAreWe = "Unread-List";
                                }else if(advSearch.hasAttach) {
                                    whereAreWe = "Attachment-List";
                                }
                            }
                        }
                        showContent('mail', html);
                        loading.hide();
//                        if (Layout.fixContentHeight) {
//                            Layout.fixContentHeight();
//                        }
//                        Metronic.initUniform();
                        CD.overlayHide();
                    });

                },
                error: function (xhr, ajaxOptions, thrownError) {

                    CD.overlayHide();
                }
            });
        });

        $('body').on('change', '.mail-group-checkbox', function () {
            var set = $('.mail-checkbox');
            var checked = $(this).is(":checked");
            $(set).each(function () {
                $(this).prop("checked", checked);
            });
        });
    };

    var loadPage = function (el, type, title, menu, callback) {
        CD.setActive(0);
        var url = 'mail/' + type;

        $(".Metronic-alerts").remove();

        $('.mail-search-form').hide();
        $('.inbox-header > h2').text(title).show();

        clearContent(function() {
            toggleButton(el);
            menuTop(menu + '-menu-item');
            //showMenu(menu);
            leftMenu(type);
            showSection(type);
            pageType = type;

            if (type === 'storage' && KRYPTOS.Storage.hasInit()) {
                return;
            }
            loading.show();

            $.ajax({
                type: "GET",
                cache: false,
                url: url,
                dataType: "html",
                success: function (res) {
                    toggleButton(el);
                    loading.hide();
                    showContent(type, res);
                    if (callback) {
                        callback();
                    }
                },
                error: function (xhr, ajaxOptions, thrownError) {
                    toggleButton(el);
                },
                async: true
            });
        });

    };

    var loadMessage = function (el, messageId, from, to, cc, type, isUnread, recipientType) {
        CD.setActive(0);
        loading.show();
        CD.overlayShow();
        clearContent(function() {
            toggleButton(el);
            //showMenu('mail');
            $('.mail-search-form').hide();
            $('.inbox-header > h2').text('').hide();
//            if (isUnread) {
//                KRYPTOS.Messages.read(recipientType + ':' + messageId, function(result) {});
//            }
            var json = KRYPTOS.Messages.get(messageId, type);
            if (json) {
                showMail(json, messageId, from, to, cc);
                toggleButton(el);
                if (!json.is_read) {
                    KRYPTOS.Messages.read(json.recipient_type + ':' + messageId, function(result) {});
                }
            }
            else if (type === 'system' || type === 'notification') {
                $.getJSON('/messages/mail?type=' + type + '&message_id=' + messageId, function(message) {
                    from = "The Tep Team";
                    showMail(message, messageId, from, to, cc);
                    toggleButton(el);
                    KRYPTOS.Messages.add(messageId, message);
                });
            }
            else {
                KU.getMessage(messageId, from, function (json) {
                    KRYPTOS.Messages.add(messageId, json);
                    showMail(json, messageId, from, to, cc);
                    toggleButton(el);
                });
            }
        });
    };

    var initEditor = function() {
        editor = new Editor();
        editor.init('eg-basic', {heightMin: 375, height: 375, heightMax: 575});
    };

    var initTagit = function(to, cc1, cc2, bcc) {
		//to = extractDisplayNameFromFullName(to);
        var allContacts = [];

        var contactGroups = Groups.getEmailGroups(); //KRYPTOS.ContactsGroups.getAllGroups();
        if (contactGroups) {
            contactGroups.forEach(function (group) {
                if (group.members) {
                    allContacts.push({label: group.name, value: group.members, type: 'group'});
                }
            });
        }

        var temp = Contacts.getContacts();
        if (temp) {
            temp.forEach(function (ct) {
                var tempElement = {};
                //tempElement = {labefroml: ct.contact.display_name + " @"+ct.contact.username, value: ct.contact.display_name + " @"+ct.contact.username, type:'contact'};
                tempElement = {label: ct.contact.username, value: ct.contact.username, type:'contact'};
//                if (ct.contact.display_name) {
//                    var dn = KU.decodeURIComp(null, ct.contact.display_name, 'subj');
//                    tempElement = {label: dn + ' (@' + ct.contact.username + ')', value: dn + ' (@' + ct.contact.username + ')', type:'contact'};
//                } else {
//                    tempElement = {label: ct.contact.username, value: ct.contact.username, type:'contact'};
//                }
                allContacts.push(tempElement);
            });
        }
        $.ui.autocomplete.prototype._renderItem = function(ul, item) {
            var regexp = new RegExp(this.term);
            var highlightedVal = item.label.replace(regexp, "<span style='font-weight:bold;color:black'>" + this.term + "</span>");
            var strIcon = "";
            if ($.isArray(item.value) ) {
                strIcon = '<i class="fa fa-users"></i>';
            } else {
                strIcon = '<i class="fa fa-user"></i>'
            }

            return $("<li'></li>")
                .data("item.autocomplete", item)
                //.append("<a><img class='autocompleteUserAvatar' src='" + item.icon + "' />" + highlightedVal + "</a>")
                .append("<a>" + strIcon + ' ' + highlightedVal + "</a>")
                .appendTo(ul);
        };

        $.ui.tagit.prototype._findTagByLabel = function(name) {
            var that = this;
            var tag = null;
            //var tmpName = null;
//            if (KU.isItAnEmail(name) && name.indexOf(',') === -1 ) {
//                tmpName = KU.extractDisplayNameFromFullName(name);
//                if (tmpName) {
//                    name = tmpName;
//                }
//            }
            this._tags().each(function(i) {
                if (that._formatStr(name) === that._formatStr(that.tagLabel(this))) {
                    tag = $(this);
                    return false;
                }
            });
            return tag;
        };

        $('#to').tagit({
            //availableTags: gotAllEmails,
            availableTags: allContacts,
            singleField: true,
            caseSensitive: false,
            allowSpaces: true,
            allowDuplicates: false,
            removeConfirmation: true,
            autocomplete: { delay: 0,
                            minLength: 2
            },
            tagSource: function(search, showChoices) {
                tagitTagSource(search, showChoices, this.options.availableTags, this);
            },
            beforeTagAdded: function(event, ui) {
                return tagitBeforeHelper(event, ui, $('#to'));
            },
            afterTagAdded: function(event, ui) {
                return tagitAfterHelper(event, ui, $('#to'));
            },
            beforeTagRemoved: function(event, ui) {
                var rem = ui.tag[0].title;
                $('li[title="'+rem+'"] span.tagit-label').text(rem);
            }
        });
        if (to) {
            var toa;
            try {
                toa = to.split(",");
            } catch (eer) {
                toa = to;
            }
            for (var i = 0; i < toa.length; i++) {
                $('#to').tagit('createTag', toa[i]);
            }
        }

        $('#cc').tagit({
            //availableTags: gotAllEmails,
            availableTags: allContacts,
            singleField: true,
            caseSensitive: false,
            allowSpaces: true,
            removeConfirmation: true,
            allowDuplicates: false,
            autocomplete: {delay: 0, minLength: 2, autoFocus: true, },
            tagSource: function(search, showChoices) {
                tagitTagSource(search, showChoices, this.options.availableTags, this);
            },
            beforeTagAdded: function(event, ui) {
                return tagitBeforeHelper(event, ui, $('#cc'));
            },
            afterTagAdded: function(event, ui) {
                return tagitAfterHelper(event, ui, $('#cc'));
            },
            beforeTagRemoved: function(event, ui) {
                var rem = ui.tag[0].title;
                $('li[title="'+rem+'"] span.tagit-label').text(rem);
            }
        });
        if (cc1) {
            var cc1a = cc1.split(",");
            for (var i = 0; i < cc1a.length; i++) {
                $('#cc').tagit('createTag', cc1a[i]);
            }
        }
        if (cc2) {
            var cc2a = cc2.split(",");
            for (var i = 0; i < cc2a.length; i++) {
                $('#cc').tagit('createTag', cc2a[i]);
            }
        }
        $('#bcc').tagit({
            //availableTags: gotAllEmails,
            availableTags: allContacts,
            singleField: true,
            caseSensitive: false,
            allowSpaces: true,
            removeConfirmation: true,
            allowDuplicates: false,
            autocomplete: {delay: 0, minLength: 2},
            tagSource: function(search, showChoices) {
                tagitTagSource(search, showChoices, this.options.availableTags, this);
            },
            beforeTagAdded: function(event, ui) {
                return tagitBeforeHelper(event, ui, $('#bcc'));
            },
            afterTagAdded: function(event, ui) {
                return tagitAfterHelper(event, ui, $('#bcc'));
            },
            beforeTagRemoved: function(event, ui) {
                var rem = ui.tag[0].title;
                $('li[title="'+rem+'"] span.tagit-label').text(rem);
            }
        });
        if (bcc) {
            var bcc1 = bcc.split(",");
            for (var i = 0; i < bcc1.length; i++) {
                $('#bcc').tagit('createTag', bcc1[i]);
            }
        }



    };

    var initRecipientsDrop = function() {
        var dropRecipientsTo = document.getElementById("recipients-to");
        var dropRecipientsCC = document.getElementById("recipients-cc");
        var dropRecipientsBCC = document.getElementById("recipients-bcc");

        if (dropRecipientsTo !== null) {
            dropRecipientsTo.addEventListener("dragenter", dragenter, false);
            dropRecipientsTo.addEventListener("dragleave", dragleave, false);
            dropRecipientsTo.addEventListener("dragover", dragover, false);
            dropRecipientsTo.addEventListener("drop", dropTo, false);
        }

        if (dropRecipientsCC !== null) {
            dropRecipientsCC.addEventListener("dragenter", dragenter, false);
            dropRecipientsCC.addEventListener("dragleave", dragleave, false);
            dropRecipientsCC.addEventListener("dragover", dragover, false);
            dropRecipientsCC.addEventListener("drop", dropCC, false);
        }

        if (dropRecipientsBCC !== null) {
            dropRecipientsBCC.addEventListener("dragenter", dragenter, false);
            dropRecipientsBCC.addEventListener("dragleave", dragleave, false);
            dropRecipientsBCC.addEventListener("dragover", dragover, false);
            dropRecipientsBCC.addEventListener("drop", dropBCC, false);
        }
    };

    var dragenter = function(e) {
        e.stopPropagation();
        e.preventDefault();
    };

    var dragleave = function(e) {
        e.stopPropagation();
        e.preventDefault();
    };

    var dragover = function(e) {
        e.stopPropagation();
        e.preventDefault();
    };

    var dropTo = function(e) {
        e.stopPropagation();
        e.preventDefault();
        tagitMoveTagTo(KRYPTOS.Email.dragSourceElement, 'to');
    };

    var dropCC = function(e) {
        e.stopPropagation();
        e.preventDefault();
        tagitMoveTagTo(KRYPTOS.Email.dragSourceElement, 'cc');
    };

    var dropBCC = function(e) {
        e.stopPropagation();
        e.preventDefault();
        tagitMoveTagTo(KRYPTOS.Email.dragSourceElement, 'bcc');
    };

    var tagitMoveTagTo = function (ttag, recip) {
        var tags = null;
        var tag = ttag.title;
        var tagObj = ttag;
        if (recip === 'to') {
            tags = $('#to').tagit("assignedTags");
            if (tags.indexOf(tag) != -1){
                return
            }
            tagitRemoveTagFrom(tagObj, $('#cc'));
            tagitRemoveTagFrom(tagObj, $('#bcc'));
            tagitAddTagTo(tag, $('#to'));
        }
        if (recip === 'cc') {
            tags = $('#cc').tagit("assignedTags");
            if (tags.indexOf(tag) != -1){
                return
            }
            tagitRemoveTagFrom(tagObj, $('#to'));
            tagitRemoveTagFrom(tagObj, $('#bcc'));
            tagitAddTagTo(tag, $('#cc'));
        }
        if (recip === 'bcc') {
            tags = $('#bcc').tagit("assignedTags");
            if (tags.indexOf(tag) != -1){
                return
            }
            tagitRemoveTagFrom(tagObj, $('#to'));
            tagitRemoveTagFrom(tagObj, $('#cc'));
            tagitAddTagTo(tag, $('#bcc'));
        }
    };

    var tagitRemoveTagFrom = function (tagObj, tagContainer) {
        var tags = tagContainer.tagit("assignedTags");
        if (tags.indexOf(tagObj.title) != -1){
            tagContainer.tagit("removeTag", tagObj);
        }
    };

    var tagitAddTagTo = function (tag, tagContainer) {
        tagContainer.tagit("createTag", tag);
    };

    var pollCurrentEmailList = function(){
        var toEl = $('input#to').val();
        var ccEl = $('input#cc').val();
        var bccEl = $('input#bcc').val();
        emailList = '';
        if(!!toEl) {
            emailList = toEl;
            if(!!ccEl || !!bccEl) emailList += ',';
        }
        if(!!ccEl) {
            emailList += ccEl;
            if(!!bccEl) emailList += ',';
        }
        if(!!bccEl) emailList += bccEl;

//        if (emailList === '') {
//            recipientsSecure = null;
//            displayMailUnsafeUI(false);
//            return;
//        }
        var emailArray = emailList.split(",");

//        $.each(emailArray, function(i, val) {
////
//        });
    };

    var tagitTagSource = function(search, showChoices, availableTags, tagitObject) {
        var filter = search.term.toLowerCase();
        var choices = $.grep(availableTags, function(element) {
                return element.label && (element.label.toLowerCase().match(filter) !== null);
            });
        var newChoices = [];
        choices.forEach(function (choice){
            if (choice.type === 'contact') {
                if ($.inArray(choice.value, tagitObject.assignedTags()) == -1){
                    newChoices.push(choice);
                }
            } else
            if (choice.type === 'group' ) {
                var members = choice.value.length;
                var found = 0;
                choice.value.forEach(function (c) {
                    if ($.inArray(c, tagitObject.assignedTags()) != -1) {
                        found++;
                    }
                });
                if (found < members) {
                    newChoices.push(choice);
                }
            }
        });
        //showChoices(tagitObject._subtractArray(choices, tagitObject.assignedTags()));
        showChoices(newChoices);
    };

    var tagitBeforeHelper = function(event, ui, selector) {
        if (!ui.duringInitialization) {
           pollCurrentEmailList();
            var tagArray = ui.tagLabel.split(/[,|;]+/);
			 if (tagArray.length>1) {
                for (var i=0,max=tagArray.length;i<max;i++) {
                    var CurrEmail = tagArray[i];
                  //  if(KU.isItAnEmail(CurrEmail)){
                        selector.tagit("createTag", tagArray[i]);
                  //  }
                }
                return false;
            } else {
			    /*
                 if(KU.isItAnEmail(tagArray)){

                 }  else {
                     // assume group
                     return false;
                 }
                */
			}
            var FullName = ui.tagLabel;
            var Name = KU.extractDisplayNameFromFullName(ui.tagLabel);
            var Email = false;
            if (!Name) {
                if (KU.isItAnEmail(ui.tagLabel)) Email = ui.tagLabel;
            } else {
                Email = KU.extractEmailFromFullName(ui.tagLabel);
            }
            ui.tag[0].setAttribute('title', FullName);
            if (Name) {
                ui.tag[0].firstChild.textContent = Name;
            } else {
                ui.tag[0].firstChild.textContent = Email;
            }
            //esa variable full name debe tener el contenido que quieres que muestre
            ui.tag[0].setAttribute('data-email', FullName);
            ui.tag[0].setAttribute('draggable', 'true');
        }
    };

    var tagitAfterHelper = function(event, ui, selector) {
        if(recipientsSecure) {
            $('i.epadlock').addClass('fa-lock-alt').css('color', '#3B4D64').attr('title', 'Encrypted');
        }
        else {
            $('i.epadlock').addClass('fa-unlock-alt').css('color', '#D4242F').attr('title', 'Unencrypted');;
        }
    };

    var attachmentsMeta = [];
    var maxSize = 104857600; //100*1024*1024;
    var totalSize = 0;
    var files = null;

    var initFileUpload = function () {
        attachmentsMeta = [];
        totalSize = 0;

        $('#fileupload').on('change', function() {
            //for (var i=0; i < this.files.length; i++) {
            //    files.push(this.files[i]);
            //}
            files = this.files;

            for (var i = 0; i < files.length; i++) {
                var duplicate = false;
                for (var j = 0; j < attachmentsMeta.length; j++) {
                    if (attachmentsMeta[j].name === files[i].name) {
                        duplicate = true;
                        showErrorMessage("Duplicate attachment", KU.cleanString(files[i].name) + " has already been attached.");
                        break;
                    }
                }
                if (!duplicate) {
                    totalSize += files[i].size;
                    if (totalSize > maxSize) {
                        showErrorMessage("Max size exceeded", KU.cleanString(files[i].name) + " has not been attached. Total attachment size allowed 100MB.");
                        totalSize -= files[i].size;
                    }
                    else {
                        KU.readFile(files[i], function(blob, meta) {
                            attachmentsMeta.push(meta);
                            var fileMeta = meta;
                            fileMeta.size = KU.bytesToSize(meta.size);
                            fileMeta.url = URL.createObjectURL(new Blob([blob], {type: "application/octet-stream"}));
                            fileMeta.icon = mimeTypeToIcon(fileMeta.type);

                            var html = templateAttachmentsUpload(fileMeta);
                            $('.inbox-compose-attachment table tbody.files').append(html);

                            new KRYPTOS.Encrypter(keyStore, null, null, null).encryptFile(blob, meta.id, null, function(result) {
                                if (!result[0].status) {
                                    KU.error(showErrorMessage, 'Upload Error', result[0].message);
                                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+meta.id+'"] .progress-bar').attr('style', 'width:0%');
                                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+meta.id+'"] .progress-percent').html('0%');
                                    $('.inbox-compose-attachment table tbody.files tr td.delete button').show().click();
                                }
                                else {
                                    for (var j = 0; j < attachmentsMeta.length; j++) {
                                        if (attachmentsMeta[j].id === result[0]['id']) {

                                            attachmentsMeta[j].hmac = result[0]['hmac'];
                                            attachmentsMeta[j].key = result[0]['key'];
                                            attachmentsMeta[j].uuid = result[0]['uuid'];
                                            $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+result[0]['id']+'"]').attr('data-uuid', result[0]['uuid']);
                                            $('.inbox-compose-attachment table tbody.files tr td.uploaded button').show();
                                            $('.inbox-compose-attachment table tbody.files tr td.delete button').show();
                                        }
                                    }
                                }
                            }, function(e) {

                                if (e.lengthComputable) {
                                    var percent = Math.round(e.loaded / e.total * 100);
                                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+meta.id+'"] .progress-bar').attr('style', 'width:'+percent+'%');
                                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+meta.id+'"] .progress-percent').html(percent + '%');
                                }
                            });
                        });
                    }
                }
            }
        });

        $('.inbox-compose-attachment').on('click', 'table tbody.files tr td.delete button', function() {
            $(this).off('click');

            var $upload = $(this).parent('td').parent('tr');
            var uuid = $upload.attr('data-uuid');
            var temp = [];
            $upload.remove();
            for (var j = 0; j < attachmentsMeta.length; j++) {
                if (attachmentsMeta[j].uuid === uuid) {
                    totalSize -= attachmentsMeta[j].bytes;
                    continue;
                }
                temp.push(attachmentsMeta[j]);
            }
            attachmentsMeta = [];
            attachmentsMeta = temp;
        });
    };

    var initFileDownload = function(uuid, attachmentsMetaData, from) {

        attachmentsMeta = attachmentsMetaData;
        for (var i = 0; i< attachmentsMetaData.length; i++) {
//            attachmentsMetaData[i].name = KU.formatLine(attachmentsMetaData[i].name, 50);
            attachmentsMetaData[i].icon = mimeTypeToIcon(attachmentsMetaData[i].type);
            var html = templateAttachmentsDownload(attachmentsMetaData[i]);
            $('.inbox-compose-attachment table tbody.files').append(html);
        }
        $('.inbox-compose-attachment').off('click', 'table tbody.files tr.inactive');
        $('.inbox-compose-attachment').on('click', 'table tbody.files tr.inactive', function() {
            var $aRow = $(this);
            $aRow.removeClass('inactive');

            var fileId = $aRow.attr('data-fileid');
            var totalSize = $aRow.attr('data-size');
            var key, hmac, type;
            for (var i = 0; i< attachmentsMetaData.length; i++) {
                if (attachmentsMetaData[i]['uuid'] === fileId) {
                    type = attachmentsMetaData[i]['type'];
                    key = attachmentsMetaData[i]['key'];
                    hmac = attachmentsMetaData[i]['hmac'];
                    break;
                }
            }
            if (key && hmac) {
                $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress-bar').attr('style', 'width:0%');
                $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress-percent').html('0%');
                KU.getAttachment(uuid, fileId, key, hmac, function (success, attachment) {
                    if (success) {
//                        var url = URL.createObjectURL(new Blob([attachment], {type: type}));
                        var $fileNameSelector = $aRow.find('span.filename');
                        var fileName = $fileNameSelector.text();
//                        $fileNameSelector.html('<a href="' + url + '" download="' + fileName + '">' + fileName + '</a>');
//                        $aRow.removeClass('enabled');

                        if(navigator.vendor && navigator.vendor.indexOf('Apple') > -1) {
                            var filen = $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .name');
                            if(!filen.attr("data-cl")){
                                window.URL = window.URL || window.webkitURL;
                                var url = window.URL.createObjectURL(new Blob([attachment], {type: type}));
                                filen.attr("data-cl",'1').wrapInner('<a href="'+url+'" title="Ready to Download" data-toggle="tooltip" data-placement="right" target="_blank" style="text-decoration:none;"/>');
                                $('.inbox .name a').tooltip('show');
                            }
                        } else {
                            $aRow.find('button').html('<i class="fa fa-unlock"></i>');
                            $aRow.find('button').prop('title', 'Click on the file name to view');
                            $aRow.addClass('inactive');
                            FileViewer.open(new Blob([attachment], {type: type}), fileName);
                            //saveAs(new Blob([attachment], {type: type}), fileName);
                        }

                    }
                    else {
                        showErrorMessage("Attachment Error", attachment);
                    }
                }, function(e) {
                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress').show();
                    $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress-percent').show();
                    if (totalSize > 0) {
                        var percent = Math.round(e.loaded / totalSize * 100);
                        if (percent > 100) {
                            percent = 100;
                        }
                        $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress-bar').attr('style', 'width:'+percent+'%');
                        $('.inbox-compose-attachment table tbody.files tr[data-fileid="'+fileId+'"] .progress-percent').html(percent + '%');
                    }
                });
            }
            else {
                showErrorMessage("Attachment Not Found", "Something went wrong!");
            }
        });
    };

    var loadCompose = function (el, uuid, type, from, to, cc) {

        CD.setActive(1);
        //var url = 'mail/compose';
        attachmentsMeta = [];
        loading.show();
        clearContent(function() {
            var name = KRYPTOS.session.getItem('display_name');
            var username = KRYPTOS.session.getItem('username');
            var email = username;//name + " @" + username;
            var html = templateCompose({email: email});
            toggleButton(el);
            menuTop('compose-menu-item');
            //showMenu('mail');
            $('.mail-search-form').hide();

            // load the form via ajax (removed for handlebars)
            toggleButton(el);

            $('#email-container .inbox-nav > li.active').removeClass('active');
            $('a.compose').parent('li').addClass('active');
            if (uuid) {
                $('.inbox-header > h2').text(type).show();
            }
            else {
                $('.inbox-header > h2').text('Compose').show();
            }

            loading.hide();
            showContent('mail', html);

            initFileUpload();
            initEditor();

            // editor.froalaEditor.keypress(function (e, editor, keypressEvent) {
            //     if ((keypressEvent.keyCode == 10 || keypressEvent.keyCode == 13) && keypressEvent.ctrlKey) {
            //     }
            // });


//                    ComponentsjQueryUISliders.init();

            //if (type === 'Compose' || type === 'Forward') {
            if (type === 'Compose') {

                if (to) {
                    initTagit(to);
                    $('#subject').focus();
                } else {
                    initTagit();
                    $('ul.tagit li.tagit-new input').focus();
                }

            } else if (type === 'Forward') {
                initTagit();
                $('ul.tagit li.tagit-new input').focus();
            }

            initRecipientsDrop();
            handleCCInput();

            $('input:radio[name="autodest"]').change(function() {
                if($(this).val() === 'yes') {
                   $('#ad-slider-s').show();
                }
                if($(this).val() === 'no') {
                   $('#ad-slider-s').hide();
                }
            });

            var signature = "";

            if (KRYPTOS.session.getItem('email_signature_active')) {
                if (KRYPTOS.session.getItem('email_signature_active') === '1') {
                    signature = '<p></p><p></p>' + KRYPTOS.session.getItem('email_signature');
                }
            }

            if (uuid) {
                var messg = KRYPTOS.Messages.get(uuid);


                if (messg.text != undefined && messg.text != ""
                    && messg.body == "") {
                    try {
                        messg.body = decodeURIComponent(messg.text).replace(/\n/g, "<br />");
                    } catch (error) {
                            messg.body = KU.sanitize(sanitizer, unescape(messg.text), true);
                                messg.body = messg.body.replace(/(\r\n|\n|\r)/gm, "<br />");
                        }
                }

                if (type === 'Reply') {
                    whereAreWe = 'Compose-Reply';
                    showReply(messg, uuid, from, to || cc, decodeURIComponent(signature));
                }
                else if (type === 'Forward') {
                    whereAreWe = 'Compose-Forward';
                    showForward(messg, uuid, from, to, cc, decodeURIComponent(signature));
                }
                else {
                    whereAreWe = 'Compose-Draft';
                    var $form = $('form#compose');
                    $form.find('input[name="message_id"]').val(uuid);
                    showDraft(messg, uuid, from);
                }
            }
            if (type === 'Compose') {
                if (whereAreWe !== 'Compose-Draft') whereAreWe = 'Compose';
                if (signature !== "") {
                    editor.set(decodeURIComponent(signature));
//                                editor.froalaEditor('html.set', decodeURIComponent(signature), true);
                }
            }
        });
    };

    var handleCCInput = function () {
        var the = $('.inbox-compose .mail-to .inbox-cc'); //anchor text > open CC input
        var input = $('.inbox-compose .input-cc'); // CC input
        the.hide();
        input.show();
        $('.close', input).click(function () {
            input.hide();
            the.show();
        });
    };

    var handleBCCInput = function () {

        var the = $('.inbox-compose .mail-to .inbox-bcc');
        var input = $('.inbox-compose .input-bcc');
        the.hide();
        input.show();
        $('.close', input).click(function () {
            input.hide();
            the.show();
        });
    };

    var toggleButton = function (el) {
        if (!el) {
            return;
        }
        if (el.attr("disabled")) {
            el.attr("disabled", false);
        } else {
            el.attr("disabled", true);
        }
    };

    var menuTop = function(item) {
        $('ul.nav.navbar-nav li').removeClass('active');
        $('ul.nav.navbar-nav li a.' + item).parent('li').addClass('active');
        $('ul.nav.navbar-nav li a.' + item).addClass('active');

        // logout button in mobile menu to white (under 992px wide)
        $('ul.nav.navbar-nav li a.logout').removeClass('active');
        $('div.page-header div.container a.logout i.icon-key').removeClass('active');
        if(item === 'inbox-menu-item'){
            $('ul.nav.navbar-nav li a.logout').addClass('active');
            $('div.page-header div.container a.logout i.icon-key').addClass('active');
        }
    };

    var showMenu = function(menu) {
        $('#email-container .inbox-nav').hide();
        $('#' + menu + "-menu").show();
    };

    var showSection = function(type) {
        if (type === 'storage') {
            contentContainer.hide();
            storageContainer.show();
        }
        else {
            storageContainer.hide();
            contentContainer.show();
        }
    };

    var showContent = function(type, html) {
        if (type === 'storage') {
            if (storage.length > 0) {
                storage.html(html);
            }
        } else {
            $('#email-container .inbox-content').html(html);
        }
    };

    var clearContent = function(callback) {
        checkDraft(function() {
            $('#email-container .inbox-content').html('');
            callback();
        });
    };

    var leftMenu = function(item) {
        $('#email-container .inbox-nav > li.active').removeClass('active');
        $('#email-container .inbox-nav > li.' + item).addClass('active');
    };


    var showMail = function (json, uuid) {
        window.opener = null;
        loading.hide();
        CD.overlayHide();
        var showStarring = false;
        var showMarkUnread = true;
        var showSpam = false;

        if (json.recipient_type === 'from') {
            showStarring = false;
            showMarkUnread = false;
            showSpam = false;
        }
        else {
            showStarring = true;
            showMarkUnread = true;
            showSpam = true;
        }
//        var mailContent;
//        if (json.body) {
//            mailContent = json.body;
//        }
//        else {
//            mailContent = '';
//        }
        clearContent(function() {
//            var sanitized = "";
//            var isSystem = json.type === 'system' || json.type === 'notification';
//            try {
//                if (isSystem) {
//                    sanitized = mailContent;
//                }
//                else {
//                    sanitized = KU.sanitize(sanitizer, decodeURIComponent(mailContent), true);
//                }
//            }
//            catch (error) {
//                sanitized = KU.sanitize(sanitizer, unescape(mailContent), true);
//            }

            var replied_at = (json.replied_at_f !== null) ? json.replied_at_f  : null;

            var forwarded_at = (json.forwarded_at_f !== null) ? json.forwarded_at_f  : null;


            var to = JSON.parse(json.to);

            var cc = JSON.parse(json.cc);

            var bcc = JSON.parse(json.bcc);

            var html = templateViewMail({
                page: currentPage,
                type: currentType,
                //recipient: currentRecipient,
                recipient: advSearchParams,
                uuid: uuid,
                subject: json.subject,
                //subject: KU.formatSubject(sanitizer, json.subject, 'subj'),
                recipient_type: json.recipient_type,
                from: json.from,
                to: to,
                cc: cc,
                bcc: bcc,
                show_starring: showStarring && !json.is_spam,
                show_spam: showSpam,
                is_starred: json.is_starred,
                is_spam: json.is_spam,
                show_markunread: showMarkUnread,
                tof: KU.formatEmails(to),
                ccf: KU.formatEmails(cc),
                bccf: KU.formatEmails(bcc),
                replied_at: replied_at,
                forwarded_at: forwarded_at,
                timestamp: new Date(json.timestamp).toDateString() + ' ' + new Date(json.timestamp).toLocaleTimeString(),
                body: json.body_sanitized || json.body,//decodeURIComponent(json.body),
                body_preview: json.body_preview,
                has_attachments: json.attachments && !KU.isEmpty(json.attachments_meta),
                attachments: json.attachments,
                is_trashed: json.is_trashed
            });
            showContent('mail', html);
            if (json.attachments_meta) {
                // Decode attachment names
                for (var j = 0; j < json.attachments_meta.length; j++) {
                    json.attachments_meta[j].name = decodeURIComponent(json.attachments_meta[j].name);
                }
                initFileDownload(uuid, json.attachments_meta, json.from);
            }
            CommonDashboard.scrollTop();
            CommonDashboard.setCurrentPage("view-mail");
        });
        // KU.replaceDisabledImgUrls(
    };

    var showReply = function (json, uuid, from, replyAll, signature) {
        if (replyAll) {
            var to = JSON.parse(json.to), cc = JSON.parse(json.cc);
            var me = CD.getUsername();
            if (json.recipient_type === 'to' && !KU.isEmpty(to)) {
                for (var i = 0; i < to.length; i++) {
                    //if (to[i] === me) {
                    if (to[i].indexOf(me) > -1) {
                        delete to[i];
                    }
                }
            }
            else if (json.recipient_type === 'cc' && !KU.isEmpty(cc)) {
                for (var i = 0; i < cc.length; i++) {
                    //if (cc[i] === me) {
                    if (cc[i].indexOf(me) > -1) {
                        delete cc[i];
                    }
                }
            }

            if (!KU.isEmpty(to) || !KU.isEmpty(cc)) {
                handleCCInput();
            }
            initTagit(from, to.toString(), (cc ? cc.toString() : cc) );
        }
        else {
            initTagit(from);
        }


        //$('textarea#message').css('visibility', 'hidden');

        $('input[name=message_id]').attr("data-reply", true);
        $('input[name=message_id]').attr("data-reply-id", uuid);


        var subject = json.subject;
        if(subject.indexOf("RE: ") === -1) {
            subject = "RE: " + subject;
        }
        $('input#subject').val(subject);
        var timeFrom = KU.timestamp(json.timestamp) + ' from ' + KU.escapeHTML(from);
//        var editorContent = signature + "<br><br>" + timeFrom + "<br>------------------------------<br>" + KU.sanitize(sanitizer, decodeURIComponent(json.body), true);
        var editorContent = signature + "<br><br>" + timeFrom + "<br>------------------------------<br>" + KU.decodeURIComp(sanitizer, json.body, json.type);
        //editorContent = KU.replaceImgUrls(editorContent);

        editor.focusContent(editorContent);
//        editor.focus();
        if (KU.hasImgUrls(editorContent)) {
            $('.inbox .block-images-compose').show();
        }

    };

    var showForward = function (json, uuid, from, to, cc, signature) {
        var recipients = "";
        if (to) {
            recipients += "To: " + KU.escapeHTML(to);
        }
        if (cc) {
            recipients +=  "<br>" + "Cc: " + KU.escapeHTML(cc);
        }

        var subject = json.subject;
        if (subject.indexOf("FW: ") === -1) {
            subject = "FW: " + subject;
        }
        $('input#subject').val(subject);

        $('input[name=message_id]').attr("data-forward", true);
        $('input[name=message_id]').attr("data-forward-id", uuid);

        var timestamp = KU.timestamp(json.timestamp);
        var editorContent = signature + "<br><br>------------ Forwarded message ------------"+
            "<br>From: " + KU.escapeHTML(from) +
            "<br>Date: " + timestamp +
            "<br>" + recipients +
            "<br>Subject: " + KU.escapeHTML(subject) +
            "<br><br>" +
            KU.decodeURIComp(sanitizer, json.body, json.type);
        //editorContent = KU.replaceImgUrls(editorContent);
            editor.set(editorContent);
//        editor.froalaEditor('html.set', editorContent, true);
        if (KU.hasImgUrls(editorContent)) {
            $('.inbox .block-images-compose').show();
        }
        if (json.attachments_meta) {
            initFileDownload(uuid, json.attachments_meta, from);
        }

    };

    var showDraft = function (json, uuid, from) {
        var to = JSON.parse(json.to), cc = JSON.parse(json.cc), bcc = JSON.parse(json.bcc);


        if (!KU.isEmpty(cc)) {
            handleCCInput();
        }
        if (!KU.isEmpty(bcc)) {
            handleBCCInput();
        }

        initTagit(null, cc.toString(), null, bcc.toString());

        var subject = json.subject;

        //$('textarea#message').css('visibility', 'hidden');
        $('input#subject').val(subject);


        if(json.replied_at != null) {
            if(json.reply_to) {
                $('input[name=message_id]').attr("data-reply", true);
                $('input[name=message_id]').attr("data-reply-id", json.reply_to);
            }
        }

         if(json.forwarded_at != null) {
            if(json.forward_to) {
                $('input[name=message_id]').attr("data-forward", true);
                $('input[name=message_id]').attr("data-forward-id", json.forward_to);
            }
        }




//        var editorContent = decodeURIComponent(KU.unescapeJson(json.body));
        var editorContent = KU.decodeURIComp(sanitizer, json.body, json.type);
        editor.focusContent(editorContent);

        if (json.attachments_meta) {
            attachmentsMeta = json.attachments_meta;
            initFileDownload(uuid, json.attachments_meta, from);
        }

        if (KU.hasImgUrls(editorContent)) {
            $('.inbox .block-images-compose').show();
        }

    };

    var confirmDeletionDialog = function(uuid, callback) {
        $('#confirm-deletion').modal({
            keyboard: true,
            show: true
        });
        $('button#confirm-delete').on('click', function() {
            $(this).off('click');
            var $input = $(this);
            $input.text('Deleting, please wait...');
            $input.prop('disabled', true);
            if (uuid !== 'draft:') {
                KRYPTOS.Messages.delete(uuid, function(result) {
                    $input.text('Confirm Delete');
                    $input.prop('disabled', false);
                    if (result) {
                        if (callback) {
                            callback();
                        }
                        else {
                            //loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, currentPage, currentRecipient);
                            if (whereAreWe === 'Compose-Draft' || whereAreWe === 'Draft-List' || whereAreWe === 'drafts') {
                                loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'drafts');
                            }else if(whereAreWe === 'Starred-List' || whereAreWe === 'starred'){
                                loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'starred');
                            }else if(whereAreWe === 'sent'){
                                loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'sent');
                            }else if(whereAreWe === "Unread-List") {
                                $('#advance-search-form')[0].reset();
                                clearDatePickersAndCheckBoxes();
                                advSearchParams = null;
                                var advSearch = {
                                    searchtype: 'advance',
                                    folder:     'inbox',
                                    isUnread:    true
                                };
                                $('#advance-search-form #adv-search-isUnread').prop('checked', true);
                                $('#adv-search-isUnread')[0].checked = true;
                                loadInbox($(this), 'inbox', 1, advSearch);
                            }else if(whereAreWe === "Attachment-List") {
                                $('#advance-search-form')[0].reset();
                                clearDatePickersAndCheckBoxes();
                                advSearchParams = null;
                                var advSearch = {
                                    searchtype: 'advance',
                                    folder:     'inbox',
                                    hasAttach:   true
                                };
                                $('#advance-search-form #adv-search-hasAttachements').prop('checked', true);
                                $('#adv-search-hasAttachements')[0].checked = true;
                                loadInbox($(this), 'inbox', 1, advSearch);
                            }else if(whereAreWe === "Trash-List" || whereAreWe === "trash"){
                                loadInbox($(this), 'trash');
                            } else {
                                loadInbox($(this), 'inbox');
                            }
                        }
                    }
                    $('#confirm-deletion').modal('hide');
                });
            } else {
                $input.text('Confirm Delete');
                $input.prop('disabled', false);
                if (whereAreWe === 'Compose-Draft') {
                    loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'drafts');
                } else {
                    loadInbox($(this), 'inbox');
                }
                $('#confirm-deletion').modal('hide');
            }
        });
    };

//
//    var filterContacts = function(opt) {
//        loadContactsPage($('a.contacts-menu-item'), 'contacts', 'Contacts', 'contacts', function() {
//            var rosters = $('#jsxc_buddylist li.jsxc_rosteritem');
//            rosters.each(function(index, item) {
//                var bid = $(item).attr('data-bid');
//                var status = $(item).attr('data-status');
//                var username = KU.e2u(bid);
//                var selector = username.replace(".", "\\.");
//                if (opt === 'offline' && status === opt ) {
//                    $('.inbox #contact-' + selector + ' .status').html(KRYPTOS.ChatCall.getContactStatus(status, false));
//                } else if (opt === 'online' && (status === opt || status === 'dnd' || status === 'away')) {
//                    $('.inbox #contact-' + selector + ' .status').html(KRYPTOS.ChatCall.getContactStatus(status, false));
//                } else {
//                    $('.inbox #contact-' + selector + ' .status').parent().remove();
//                    // $('.inbox #contact-' + selector + ' .status').html(KRYPTOS.ChatCall.getContactStatus(status, false));
//                }
//            });
//        });
//
//    };


    var saveDraft = function(callback, showError) {
        var $form = $('form#compose');
        var $button = $form.find('button.save-draft');
        var btnText = $button.find('span').text();
        $button.find('span').text('Saving...');
        var $deleteButton = $form.find('button.inbox-discard-btn');
        $button.prop('disabled', true);
        $deleteButton.prop('disabled', true);
        var from = $form.find('input[name="from"]').val();

        var to = $form.find('input[name="to"]').val();
        var cc = $form.find('input[name="cc"]').val();
        var bcc = $form.find('input[name="bcc"]').val();
        var usec = $form.find('input[name="usec"]').val();
        var fSubject = $form.find('input[name="subject"]').val();
        var uuid = $form.find('input[name="message_id"]').val();
        var plain = editor.get();
//        var plain = editor.froalaEditor('html.get', false, false);
        var autosave = to || cc || bcc || usec || fSubject || plain || attachmentsMeta.length;

        if (autosave) {
            var recipients = {
                to: [],
                cc: [],
                bcc: [],
                from: [from]
            };

            if (to) {
               //recipients.to = to.toLowerCase().split(",");
               recipients.to = to.split(",");
            }
            if (cc) {
                //recipients.cc = cc.toLowerCase().split(",");
                recipients.cc = cc.split(",");
            }
            if (bcc) {
                //recipients.bcc = bcc.toLowerCase().split(",");
                recipients.bcc = bcc.split(",");
            }

            // Check if some attachments are still uploading
            if (!KU.isEmpty(attachmentsMeta)) {
                for (var j = 0; j < attachmentsMeta.length; j++) {
                    if (attachmentsMeta[j].uuid === null) {
                        //showErrorMessage("Attachments not uploaded yet", "Please wait for the attachments to finish uploading.");
                        $button.prop('disabled', false);
                        $deleteButton.prop('disabled', false);
                        $button.find('span').text(btnText);
                        return;
                    }
                }
            }

//           KRYPTOS.Keys.getRecipientsPublicKeys([from], function(success, message) {
//            //KRYPTOS.Keys.getRecipientsPublicKeys(emails, function(success, message) {
//
//            // Display Name: Convert Full Emails into Emails
//            for (var i = 0; i < emails.length; i++){
//                var tmpEmail = KU.extractEmailFromFullName(emails[i]);
//                if (tmpEmail) {
//                    emails[i] = tmpEmail;
//                }
//            }
            var username = KU.extractUsernameFromFullName(from);
            keyStore.getRecipientsPublicKeys([username], function(success, message) {
//            keyStore.getRecipientsPublicKeys([from, KU.extractEmailFromFullName(recipients.to)], function(success, message) {
                if (!success) {
                    $button.prop('disabled', false);
                    $deleteButton.prop('disabled', false);
                    $button.find('span').text(btnText);
                    $form.find('textarea, input').prop('disabled', false);
                    if (showError) {
                        showErrorMessage("Draft Not Saved!", message.errors.username);
                    }
                }
                else {
                    var plainText = {
                        timestamp: new Date().getTime(),
                        subject: encodeURIComponent(fSubject),
                        body: encodeURIComponent(plain),
                        attachments: attachmentsMeta,
                        reply_to: null,
                        forward_to: null
                    };


                    if ($form.find('input[name="message_id"]').attr('data-reply')) {
                        plainText.reply_to = $form.find('input[name="message_id"]').attr('data-reply-id');
                    }

                    if ($form.find('input[name="message_id"]').attr('data-forward')) {
                        plainText.forward_to = $form.find('input[name="message_id"]').attr('data-forward-id');
                    }

                    var Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, recipients, function(success, message) {
                        if (success) {
                            if (message.uuid) {
                                $form.find('input[name="message_id"]').val(message.uuid);
                            }
                        }
                        else {
                            $form.find('textarea, input').prop('disabled', false);
                            if (showError) {
                                KU.error(showErrorMessage, 'Draft Not Saved!', message);
                            }
                        }
                        $button.prop('disabled', false);
                        $deleteButton.prop('disabled', false);
                        $button.find('span').text(btnText);
                        if (callback) {
                            callback(success);
                        }
                    });

                    var data = {};

                    if ($form.find('input[name="message_id"]').attr('data-reply')) {
                        data['reply'] = $form.find('input[name="message_id"]').attr('data-reply-id');
                        //plainText.reply_to = data['reply'];
                    }

                    if ($form.find('input[name="message_id"]').attr('data-forward')) {
                        data['forward'] = $form.find('input[name="message_id"]').attr('data-forward-id');
                        //plainText.forward_to = data['forward'];
                    }

                    if(uuid) {
                        data['uuid'] = uuid;
                    }

                    Encrypter.encrypt('draft', data);

                }

            });
        }
        else {
            $button.prop('disabled', false);
            $deleteButton.prop('disabled', false);
            $button.find('span').text(btnText);
            if (callback) {
                callback(true);
            }
        }
    };

    var sendAutoMail = function(subject, emails, recipients, content) {
        keyStore.getRecipientsPublicKeys(emails, function(success, message) {

            if (!success) {

                showErrorMessage("Email Not Sent!", message);
            } else {
                var plainText = {
                    timestamp: new Date().getTime(),
                    subject: encodeURIComponent(subject),
                    to: "",//KU.u2e(KU.escapeHTML(to)),
                    body: encodeURIComponent(content),
                    attachments: []
                };

                var Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, recipients, function(success, error) {
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

    var sendMail = function() {
        var $form = $('form#compose');
        var $button = $form.find('button.send');
        var $buttonDraft = $form.find('button.save-draft');
        var from = $form.find('input[name="from"]').val();

        var to = $form.find('input[name="to"]').val();
        var cc = $form.find('input[name="cc"]').val();
        var bcc = $form.find('input[name="bcc"]').val();


        var fSubject = $form.find('input[name="subject"]').val();
        var plain = editor.get();
//        var plain = editor.froalaEditor('html.get', false, true);
        // Check if any recipients
        if (to === '' && cc === '' && bcc === '') {
            showErrorMessage("No recipients", "Please specify at least one recipient.");
            return;
        }

        // if (fSubject === '') {
        //     showErrorMessage("No Subject", "Please write a Subject for the Email.");
        //     return;
        // }

//        if (plain === '') {
//            showErrorMessage("No Message", "Please write a Message for the Email.");
//            return;
//        }

        var recipients = {
            to: [],
            cc: [],
            bcc: [],
            from: [from]
        };



        var emails = [from];
        if (to) {
           //recipients.to = to.toLowerCase().split(",");
           recipients.to = to.split(",");
           emails = emails.concat(recipients.to);
        }
        if (cc) {
            //recipients.cc = cc.toLowerCase().split(",");
            recipients.cc = cc.split(",");
            emails = emails.concat(recipients.cc);
        }
        if (bcc) {
            //recipients.bcc = bcc.toLowerCase().split(",");
            recipients.bcc = bcc.split(",");
            emails = emails.concat(recipients.bcc);
        }

        // Check if some attachments are still uploading
        if (!KU.isEmpty(attachmentsMeta)) {
            for (var j = 0; j < attachmentsMeta.length; j++) {
                if (attachmentsMeta[j].uuid === null) {
                    showErrorMessage("Attachments not uploaded yet", "Please wait for the attachments to finish uploading.");
                    return;
                }
            }
        }

        $buttonDraft.prop('disabled', true);
        $button.prop('disabled', true);
        //Start spinner
        CD.overlayShow();
        var uuid =  $form.find('input[name="message_id"]').val();

        // Display Name: Convert Full Emails into Emails
        for (var i = 0; i < emails.length; i++){
            var tmpEmail = KU.extractUsernameFromFullName(emails[i]);
            if (tmpEmail) {
                emails[i] = tmpEmail;
            }
        }


        keyStore.getRecipientsPublicKeys(emails, function(success, message) {

            if (!success) {
                $button.prop('disabled', false);
                $buttonDraft.prop('disabled', false);
                $form.find('textarea, input').prop('disabled', false);
                showErrorMessage("Email Not Sent!", message.errors.username);
            } else {
                // Encode attachment names
                for (var j = 0; j < attachmentsMeta.length; j++) {
                    attachmentsMeta[j].name = encodeURIComponent(attachmentsMeta[j].name);
                }
                var plainText = {
                    timestamp: new Date().getTime(),
                    subject: encodeURIComponent(fSubject),
                    to: "",//KU.u2e(KU.escapeHTML(to)),
                    body: encodeURIComponent(plain),
                    attachments: attachmentsMeta
                };

                for (var i = 0; i < attachmentsMeta.length; i++) {
                    attachmentsMeta[i].objFile = null;
                }

                var Encrypter = new KRYPTOS.Encrypter(keyStore, plainText, recipients, function(success, error) {
                    if (success) {
                        CD.setActive(0);
                        attachmentsMeta = [];

//                            showSuccessMessage("Mail Sent!", "The mail was sent successfully.");
//                         loadInbox($(this), 'inbox');
//                        KRYPTOS.Keys.getContactsPublicKeys( function() {
                            loadInbox($(this), 'inbox');
//                            setContactStatus();
//                        });
                    }
                    else {
                        $button.prop('disabled', false);
                        $buttonDraft.prop('disabled', false);
                        $form.find('textarea, input').prop('disabled', false);
                        KU.error(showErrorMessage, 'Email Not Sent!', error);
                    }
                });
                var sendData = [];

                if(uuid) {
                    sendData['uuid'] = uuid;
                }

                if ($form.find('input[name="message_id"]').attr('data-reply')) {
                    sendData['reply'] = $form.find('input[name="message_id"]').attr('data-reply-id');
                }

                if ($form.find('input[name="message_id"]').attr('data-forward')) {
                    sendData['forward'] = $form.find('input[name="message_id"]').attr('data-forward-id');
                }


                Encrypter.encrypt('message', sendData);
            }

        });
    };

    var handleBootstrapSwitch = function() {

        $('.switch-radio1').on('switch-change', function () {
            $('.switch-radio1').bootstrapSwitch('toggleRadioState');
        });

        // or
        $('.switch-radio1').on('switch-change', function () {
            $('.switch-radio1').bootstrapSwitch('toggleRadioStateAllowUncheck');
        });

        // or
        $('.switch-radio1').on('switch-change', function () {
            $('.switch-radio1').bootstrapSwitch('toggleRadioStateAllowUncheck', false);
        });

    };

    var handleEvents = function() {

        quickSearch = $('#quick-search');
        section.on('propertychange change click keyup input paste', 'input#to, input#cc, input#bcc', function(e) {
           pollCurrentEmailList();
        });

        // Stared / Un Stared
        section.on('click', 'i.fa-star, i.fa-star-o', function(e) {
            e.preventDefault();
            var $i = $(this);
            var $mid = null;
            var $tmpMail = null;
            if ($i.parent().is('a')) {
                $mid = $i.parent().attr('data-messageid');
            } else {
                $mid = $i.parent().parent().attr('data-messageid');
            }
            if ($i.hasClass('js_star-o')) {
                KRYPTOS.Messages.star($mid, function(result) {
                    if (result) {
                        // un-stared => stared
                        // update cache
                        $tmpMail = KRYPTOS.Messages.get($mid);
                        $tmpMail.is_starred = true;
                        KRYPTOS.Messages.add($mid, $tmpMail);
                        $i.removeClass('js_star-o');
                        $i.addClass('js_star');
                        $i.removeClass('fa-star-o');
                        $i.addClass('fa-star');
//                            $i.css('color', '#f7ca18');
                        // trigger database update
                    }
                });
            } else {
                KRYPTOS.Messages.unstar($mid, function(result) {
                    if (result) {
                        // stared => un-stared
                        // update cache
                        $tmpMail = KRYPTOS.Messages.get($mid);
                        $tmpMail.is_starred = false;
                        KRYPTOS.Messages.add($mid, $tmpMail);
                        $i.removeClass('js_star');
                        $i.addClass('js_star-o');
                        $i.removeClass('fa-star');
                        $i.addClass('fa-star-o');
//                            $i.css('color', '#c1c1c1');
                        // trigger database update
                    }
                });

            }
        });

        // Handle next page load in all mailboxes
        section.on('click', 'a.btn-paging', function(e) {
            e.preventDefault();
            var $a = $(this);
            currentPage = $a.attr('data-page');
            //currentType = $a.attr('data-type');
            //currentRecipient = $a.attr('data-recipient');
            //advSearchParams = $a.attr('data-recipient');
            //loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, currentPage, currentRecipient);
            loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, currentPage, advSearchParams);
        });

        section.on('click', 'a.back-button', function(e) {
            e.preventDefault();
            var $a = $(this);
            currentPage = $a.attr('data-prev-page');
            //currentType = $a.attr('data-prev-type');
            //var currentRecipient = $a.attr('data-prev-recipient');
            //var advSearchParams = $a.attr('data-prev-recipient');
            //loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, currentPage, currentRecipient);
            loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, currentPage, advSearchParams);
        });


        $('.inbox #button-basic-search').on('click', function() {
            //var recipient = quickSearch.val();
            var advSearch = {searchtype: 'basic'};
            //advSearchParams = null;
            //if (currentType === 'sent') {
                advSearch.recipient = quickSearch.val();
            //}
            if(advSearch.recipient !== "") {
                loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, 1, advSearch);
                return false;
            }else {
                //showErrorMessage("Filter Error", "You must provide an email or name.");
            }
        });

        quickSearch.keypress(function (e) {
            if (e.which === 13) {
                $('.inbox #button-basic-search').click();
                return false;
            }
        });

        quickSearch.click(function(e) {
             e.stopPropagation();
            if (quickSearch.prop('data-type') === 'advanced') {
                quickSearch.val('');
                if ( $('#adv-search .dropdown').hasClass('open') ) {
                    $('.inbox #adv-search-Text').focus();
                } else {
                    $('#adv-search .dropdown-toggle').dropdown('toggle');
                    $('.inbox #adv-search-Text').focus();
                }
            }
        });

        section.on('click', '#advance-search-form-clear', function() {
            clearDatePickersAndCheckBoxes();
            quickSearch.val('');
            advSearchParams = null;
            if (currentType === 'sent') {
                quickSearch.prop('placeholder', 'Search by receiver');
                loadInbox(section.find('.inbox-nav > li.sent > a'), 'sent', null, null, true);
            } else {
                quickSearch.prop('placeholder', 'Search by sender');
                loadInbox(section.find('.inbox-nav > li.sent > a'), 'inbox', null, null, true);
            }
        });

        $('.inbox #btn-adv-search').on('click', function() {
            var advSearch = {
                searchtype: 'advance',
                //sender:      $('#advance-search-form #adv-search-Sender').val(),
                folder:     currentType,
                recipient:   $('#advance-search-form #adv-search-Text').val(),
                hasAttach:   $('#advance-search-form #adv-search-hasAttachements').is(':checked'),
                isStarred:   $('#advance-search-form #adv-search-isStarred').is(':checked'),
                isUnread:    $('#advance-search-form #adv-search-isUnread').is(':checked'),
                dateFrom:    $('#advance-search-form #adv-search-dateFrom').val(),
                dateUntil:   $('#advance-search-form #adv-search-dateUntil').val(),
            };
//            loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, 1, advSearch);
            loadInbox($('#email-container .inbox-nav > li.inbox > a'), currentType, 1, advSearch);
            return false;
        });

        section.on('click', 'tr td .click-to-mail', function() {
            var email = $(this).closest('tr').attr('data-email');
            loadCompose($(this), null, 'Compose', null, email);
        });

        section.on('click', 'span.click-to-mail', function() {
            // TODO: only if type system
            var email = $(this).attr('data-email');
            loadCompose($(this), null, 'Compose', null, email);
        });

        // handle compose btn click
        section.on('click', 'button.compose-btn, a.compose-btn', function () {
            whereAreWe = 'Compose';
            loadCompose($(this), null, 'Compose');
        });

        $('.accept-shares').on('click', function () {
            //loadPage($(this), 'accept-shares', 'Accept Shares', 'storage');
            $('#accept-shares-page').slideToggle();
        });

        $('a.toggle-controlbox').on('click', function (e) {
            e.preventDefault();
            if (chatEnabled) {
                KRYPTOS.ChatCall.toggleControl(e);
            }
        });

        // handle discard btn
        section.on('click', '.inbox-discard-btn', function (e) {
            e.preventDefault();
            var uuid = $('form#compose').find('input[name="message_id"]').val();

            confirmDeletionDialog("draft:" + uuid);

            //if (uuid) {
            //    confirmDeletionDialog("draft:" + uuid, function() {
            //        loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'drafts');
            //    });
            //}
            //else {
            //    loadInbox($(this), listListing);
            //}
        });


        // handle reply button click
        section.on('click', '.reply-btn', function () {
            loadCompose($(this), $(this).attr('data-messageid'), 'Reply', $(this).attr('data-from'), $(this).attr('data-to'), $(this).attr('data-cc'));
        });

        // handle forward button click
        section.on('click', '.forward-btn', function () {
            loadCompose($(this), $(this).attr('data-messageid'), 'Forward', $(this).attr('data-from'), $(this).attr('data-to'), $(this).attr('data-cc'));
        });

//        section.on('click', '.contacts-filter-online', function () {
//            filterContacts('online');
//        });
//
//        section.on('click', '.contacts-filter-offline', function () {
//            filterContacts('offline');
//        });
//
//        section.on('click', '.contacts-filter-all', function () {
//            loadContacts();
//            // filterContacts('all');
//        });

        // handle delete button click
        section.on('click', '.delete-btn', function () {
            var uuid = $(this).attr('data-messageid');
            if (!uuid) return;

            confirmDeletionDialog(uuid);
        });

        section.on('click', '.restore-btn', function () {
            var uuid = $(this).attr('data-messageid');
            if (!uuid) return;

            CD.overlayShow();

            KRYPTOS.Messages.restore(uuid, function(result) {
                if (result) {
                    CD.overlayHide();
                    showSuccessMessage("Mail Restored!", "The mail was successfully restored.");
                    loadInbox($(this), 'trash');
                }else {
                    showSuccessMessage("Restore Error", "Unexpected restoration error occurred.");
                }
            });
        });

        // handle print button click
        section.on('click', '.print-btn', function () {
            window.print();
        });
        section.on('click', '.unread-btn', function () {
            var uuid = $(this).attr('data-messageid');
            if (!uuid) return;

            KRYPTOS.Messages.unread(uuid, function(result) {
                loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'inbox', null, null, true);
            });
        });

        // handle multiple delete button click
        section.on('click', '.multiple-delete-btn', function () {
            var uuids = $('input.mail-checkbox:checked').map(function() {
                return this.value;
            }).get().join(',');
            if (!uuids) return;

            confirmDeletionDialog(uuids);
        });

        section.on('click', '.multiple-restore-btn', function () {
            var uuids = $('input.mail-checkbox:checked').map(function() {
                return this.value;
            }).get().join(',');
            if (!uuids) return;

            CD.overlayShow();

            KRYPTOS.Messages.restore(uuids, function(result) {
                if (result) {
                    CD.overlayHide();
                    showSuccessMessage("Mail Restored!", "The mail was successfully restored.");
                    loadInbox($(this), 'trash');
                }else {
                    showSuccessMessage("Restore Error", "Unexpected restoration error occurred.");
                }
            });
        });

        section.on('click', '.multiple-read-btn', function () {
            var uuids = $('input.mail-checkbox:checked').map(function() {
                return this.value;
            }).get().join(',');
            if (!uuids) return;
            KRYPTOS.Messages.read(uuids, function(result) {
//                loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'inbox');
                KRYPTOS.Email.forceLoadInbox();
            });
        });

        section.on('click', '.multiple-unread-btn', function () {
            var uuids = $('input.mail-checkbox:checked').map(function() {
                return this.value;
            }).get().join(',');
            if (!uuids) return;
            KRYPTOS.Messages.unread(uuids, function(result) {
                //loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'inbox', null, null, false);
                //loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'inbox');
//                CommonDashboard.mailCheck(true);
                KRYPTOS.Email.forceLoadInbox();
            });

        });

        // handle view message
        $('.inbox-content').on('click', 'tr.view-mail td.view-message', function () {
            var $el = $(this).parent('tr.view-mail');
            var messageId = $el.attr('data-messageid');
            var recipientType = $el.attr('data-recipient-type');
            var from = $el.attr('data-from');

            var to = $el.attr('data-to');
            var cc = $el.attr('data-cc');
            if (to) {
                to = JSON.parse(to);
            }
            if (cc) {
                cc = JSON.parse(cc);
            }

            var isUnread = $el.attr('data-read') === 'false';
            var type = $el.attr('data-type');

            if (recipientType === 'draft') {
                loadCompose($(this), messageId, 'Compose', from, to, cc);
            }
            else {
                loadMessage($(this), messageId, from, to, cc, type, isUnread, recipientType);
            }

            //Update the mails / counter when viewing mail.
            CommonDashboard.mailCheck(false);
        });

        $('#email-container .inbox-nav > li.password > a').on('click', function () {
            loadPage($(this), 'password', 'Change Password', 'settings');
        });

        $('a.settings-menu-item, .inbox-nav > li.settings > a').on('click', function () {
            loadPage($(this), 'settings', 'Settings', 'settings');
        });

        $('#email-container .inbox-nav > li.two-factor > a').on('click', function () {
            loadPage($(this), 'two-factor', 'Two-Factor Authentication', 'settings');
        });

        $('#email-container .inbox-nav > li.contacts-settings > a').on('click', function () {
            loadPage($(this), 'contacts-settings', 'Contacts Settings', 'settings');
        });

        $('#email-container .inbox-nav > li.billing-info > a').on('click', function () {
            loadPage($(this), 'billing-info', '', 'settings');
        });

        $('#email-container .inbox-nav > li.payments > a').on('click', function () {
            loadPage($(this), 'payments', '', 'settings');
        });

        $('#email-container .inbox-nav > li.subscription > a').on('click', function () {
            loadPage($(this), 'subscription', '', 'settings');
        });

        $('#email-container .inbox-nav > li.billing > a').on('click', function () {
            loadPage($(this), 'billing', '', 'settings');
        });

        $(document).on('click', '.invite-people', function (e) {
            e.preventDefault();
            loadInvite($(this));
            return false;
        });

        $('#email-container .inbox-nav > li.notifications > a').on('click', function () {
            loadPage($(this), 'notifications', 'Notifications Settings', 'settings');
        });

        $('#email-container .inbox-nav > li.signature > a').on('click', function () {
            loadPage($(this), 'signature', 'Email Signature', 'settings', function() {
                initEditor();

                // Decrypt Signature
                if (userSettings['settings.mail.signatures'] !== "") {
                    var messageObj = JSON.parse(userSettings['settings.mail.signatures']);
                    if (userSettings['settings.mail.signatures'] !== null) {

                        KRYPTOS.getPrivateDecryptionKey( function (success, pdk) {
                            if (!success) {
                                return;
                            }
                            messageObj.key = KU.b642ab(messageObj.k);
                            messageObj.iv = KU.b642ab(messageObj.iv);
                            messageObj.message = KU.b642ab(messageObj.m);
                            messageObj.signature = KU.b642ab(messageObj.s);

                            //var pvk = KRYPTOS.Keys.getPublicKey(from, 'verify');
                            KRYPTOS.Keys.getPublicKey(username, 'verify', function(pvk) {
                                new KRYPTOS.Decrypter(keyStore, messageObj.key, messageObj.iv, messageObj.message, messageObj.signature, pvk, pdk, function(plainText) {
                                    //               (encryptedKey  , iv           , cipherText        , signature           , theirPublicKey, privateKey, callback)

                                    if (plainText) {
                                        editor.focusContent(decodeURIComponent(plainText.text));
                                    }

                                }).decrypt();
                            });

                        });
                    }
                }
                //if (dSign != null) focusEditor(dSign);
            });
        });

        $('#email-container .inbox-nav > li.auto-destruction > a').on('click', function () {
            loadPage($(this), 'auto-destruction', 'Auto Destruction Settings', 'settings');
        });

        //$('#email-container .inbox-nav > li.signature > a').on('click', function () {
        //    loadPage($(this), 'signature', 'Signature', 'settings', function() {
        //        initEditor();
        //    });
        //});

//            $('a.contacts-menu-item').on('click', function () {
//                $('#contacts-menu .contacts').click();
//                //$('#email-container .inbox-nav > li.active').removeClass('active');
////                $('a.compose').parent('li').addClass('active');
//            });
//
        $('#contacts-menu .contacts').on('click', function() {
            loadContacts();
            $('#email-container .inbox-nav > li.active').removeClass('active');
            $('#contacts-menu .contacts').addClass('active');
        });

        $('#contacts-menu .contacts-groups').on('click', function() {
                                //(el, type, title, menu, callback)
            loadContactsGroupPage($('a.contacts-menu-item'), 'groups', 'Groups', 'contacts-groups', function() {
                //setContactStatus();
            });

            $('#email-container .inbox-nav > li.active').removeClass('active');
            $('#contacts-menu .contacts-groups').addClass('active');
            //setTimeout(function() {$('li.contacts').addClass('active');},10);
        });


        $('#invite-but, a.invite-menu-item, ul.inbox-nav > li.refer-friend > a, div#inbox-help a.refer-friend').on('click', function () {
            loadInvite($(this));
        });

        // handle inbox listing
        section.on('click', 'button.inbox', function () {
            $('#advance-search-form')[0].reset();
            clearDatePickersAndCheckBoxes();
            advSearchParams = null;
            whereAreWe = 'inbox';
            loadInbox($(this), 'inbox');
        });

        section.on('click', 'button.unread-mails', function () {
            $('#advance-search-form')[0].reset();
            clearDatePickersAndCheckBoxes();
            advSearchParams = null;
            var advSearch = {
                searchtype: 'advance',
                folder:     'inbox',
                isUnread:    true
            };
            $('#advance-search-form #adv-search-isUnread').prop('checked', true);
            whereAreWe = 'inbox';
            loadInbox($(this), 'inbox', 1, advSearch);
        });

        section.on('click', 'button.attachment-mails', function () {
            $('#advance-search-form')[0].reset();
            clearDatePickersAndCheckBoxes();
            advSearchParams = null;
            var advSearch = {
                searchtype: 'advance',
                folder:     'inbox',
                hasAttach:   true
            };
            $('#advance-search-form #adv-search-hasAttachements').prop('checked', true);
            whereAreWe = 'inbox';
            loadInbox($(this), 'inbox', 1, advSearch);
        });

        // handle sent listing
        section.on('click', 'button.sent', function () {
            $('#advance-search-form')[0].reset();
            clearDatePickersAndCheckBoxes();
            advSearchParams = null;
            loadInbox($(this), 'sent');
        });

        // handle draft listing
        section.on('click', 'button.drafts', function () {
            whereAreWe = 'Draft-List';
            loadInbox($(this), 'drafts');
        });

        section.on('click', 'button.trash', function () {
            whereAreWe = 'Trash-List';
            loadInbox($(this), 'trash');
        });

        // handle starred listing
        section.on('click', 'button.starred', function () {
            $('#advance-search-form')[0].reset();
            clearDatePickersAndCheckBoxes();
            advSearchParams = null;
            $('#adv-search-isStarred')[0].checked = true;
            whereAreWe = 'Starred-List';
            loadInbox($(this), 'starred');
        });

        $('#email-container .inbox-nav > li.spam > a').click(function () {
            whereAreWe = 'Spam-List';
            loadInbox($(this), 'spam');
        });

        // handle trash listing
        $('#email-container .inbox-nav > li.trash > a').click(function () {
            loadInbox($(this), 'trash');
        });

        //handle compose/reply cc input toggle
        $('.inbox-content').on('click', '.mail-to .inbox-cc', function () {
            handleCCInput();
        });

        //handle compose/reply bcc input toggle
        $('.inbox-content').on('click', '.mail-to .inbox-bcc', function () {
            handleBCCInput();
        });

        //$('a[href^=mailto]')
        section.on('click', '.inbox-view a', function(e) {
            e.preventDefault();
            e.stopPropagation();
            var item = $(this);
            var href = item.attr('href');
            if (href) {
                if (href.match(/^mailto:/i)) {
                    loadCompose(item, null, 'Compose', null, item.text());
                }
                else if (href.match(/^action:/i)) {
                    var url = href.split(':');
                    var query =  url[1].split(',');
//                    var action = item.data('action');
//                    var dataItem = item.data('item');
                    CommonDashboard.handleActions(query[0], query[1]);
                }
                else {
                    KU.safeOpen($(this));
                }
            }
        });

        $('body').on('click', '.jsxc_textarea a', function(e) {
            e.preventDefault();
            e.stopPropagation();
            KU.safeOpen($(this));
        });

        loadSound();

        $('.inbox-content').on('click', 'button.save-draft', function (e) {
            e.preventDefault();
            saveDraft(false, true);
        });

        $('.inbox-content').on('click', 'button.send', function (e) {
            e.preventDefault();
            sendMail();

        });

        $('#id-custom-folders').click(function(){
            $('.custom-folder').slideToggle();
        });

        handleBootstrapSwitch();

        // Load inbox
        //$('#mail-menu > li.inbox > a').click();
    };

    var compose = function(to) {
        whereAreWe = 'Compose';
        if (KU.isConference(to)) {
            var emails = Groups.getEmailsFromGroup(to);
            loadCompose(null, null, 'Compose', null, emails);
        }
        else {
            loadCompose(null, null, 'Compose', null, to);
        }
    };

    var forceLoadInbox = function(force) {
        if (force) {
            return loadInbox($('#email-container .inbox-nav > li.inbox > a'), 'inbox');
        }

        var cPage = currentPage;
        var aSParams = advSearchParams;

        if (!cPage) {
            cPage = 1;
        }
        if (!whereAreWe || aSParams) {
            whereAreWe = 'inbox';
        }

//        else if (whereAreWe !== 'sent') {
//            cPage = null;
//            aSParams = null;
//        }

        loadInbox($('#email-container .inbox-nav > li.inbox > a'), whereAreWe, cPage, aSParams);
    };

    var getMessages = function(data, callback) {


        if (data.public_keys) {
            for (var i = 0; i < data.public_keys.length; i++) {
                keyStore.setPublicKeys(data.public_keys[i].username, data.public_keys[i].public_keys);
            }
        }
        var usePDK = false;
        if (data.mails) {
            var promises = [];
            for (var i = 0; i < data.mails.length; i++) {
                if (data.mails[i].type === 'mail') {
                    usePDK = true;
                    break;
                }
            }
            if (usePDK) {
                for (var i = 0; i < data.mails.length; i++) {
                    if (data.mails[i].type === 'mail') {
                        data.mails[i].e2e = true;

                        var mail = data.mails[i];
                        var message = KU.b642ab(mail.mail);

                        //var pvk = KRYPTOS.Keys.getPublicKey(data.mails[i].username, 'verify');
//                        keyStore.getPublicKey(mail.username, 'verify', function(pvk) {
                            KU.extractMessage(message, function(encryptedKey, iv, cipherText, signature) {
                                promises.push(new KRYPTOS.Decrypter(keyStore, encryptedKey, iv, cipherText, signature, null, null, callback).decrypt2(mail.username, mail.uuid));
                            });
//                        });
                    }
                    else { // system
                        data.mails[i].e2e = true;
                        data.mails[i].subject_f = data.mails[i].subject;
                        data.mails[i].body = data.mails[i].mail;
                        data.mails[i].body_preview = $(data.mails[i].mail).text();
                        data.mails[i].display_name = data.mails[i].from;
                        data.mails[i].display_name_f = KU.formatLine(
                            KU.extractDisplayNameFromFullName(data.mails[i].from), 40);
                        KRYPTOS.Messages.add(data.mails[i].uuid, data.mails[i]);
                    }
                    //KRYPTOS.session.setItem("m" + data.mails[i].uuid, JSON.stringify(data.mails[i]));
                }
                KRYPTOS.Promise.all(promises)
                    .then(function(result) {
                        for (var i = 0; i < data.mails.length; i++) {
                            for (var j = 0; j < result.length; j++) {
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
                                        data.mails[i].subject = KU.decodeURIComp(data.sanitizer, result[j].plain.subject, 'subj');
                                        data.mails[i].subject_f = KU.formatSubject(data.sanitizer, result[j].plain.subject, 'subj');
                                    }

                                    var sanitized = "";
                                    var isSystem = data.mails[i].type === 'system' || data.mails[i].type === 'notification';
                                    try {
                                        if (isSystem) {
                                            sanitized = data.mails[i].body;
                                        }
                                        else {
                                            sanitized = KU.sanitize(sanitizer, decodeURIComponent(data.mails[i].body), true);
                                        }
                                    } catch (error) {
                                        sanitized = KU.sanitize(sanitizer, unescape(data.mails[i].body), true);
                                    }

                                    data.mails[i].body_sanitized = sanitized;
                                    var chtml = $.parseHTML(sanitized);
                                    data.mails[i].body_preview = $(chtml).text();

                                    if (result[j].plain.reply_to) {
                                        data.mails[i].reply_to = result[j].plain.reply_to;
                                    }

                                    if(result[j].plain.forward_to) {
                                        data.mails[i].forward_to = result[j].plain.forward_to;
                                    }

                                    var fromDN = KU.extractDisplayNameFromFullName(data.mails[i].from);

                                    if (!fromDN) {
                                        data.mails[i].display_name = data.mails[i].from;
                                        data.mails[i].display_name_f = KU.formatLine(data.mails[i].from, 40);
                                    } else {
                                        data.mails[i].display_name = fromDN;
                                        data.mails[i].display_name_f = KU.formatLine(fromDN, 40);
                                    }

                                    if (data.mails[i].recipients && data.mails[i].recipients.first) {
                                        var toDN = KU.extractDisplayNameFromFullName(data.mails[i].recipients.first);
                                        data.mails[i].recipients.display_name = toDN;
                                        //data.mails[i].recipients.display_name_f = KU.formatLine(toDN, 40);
                                        data.mails[i].recipients.display_name_f = "";
                                        var allrecipients = data.mails[i].recipients.all.split(',');
                                        for (var ii=0; ii < allrecipients.length; ii++ ){
                                            toDN = KU.extractDisplayNameFromFullName(allrecipients[ii]).trim();
                                            data.mails[i].recipients.display_name_f += toDN + ', ';
                                        }
                                        data.mails[i].recipients.display_name_f =
                                            data.mails[i].recipients.display_name_f.substr(0, data.mails[i].recipients.display_name_f.length -2);
                                        data.mails[i].recipients.display_name_f = KU.formatLine(data.mails[i].recipients.display_name_f, 35);
                                    }

                                    data.mails[i].failed = result[j].failed;
                                    KRYPTOS.Messages.add(data.mails[i].uuid, data.mails[i]);
                                    break;
                                }
                            }
                        }
                        callback(true, data);
                    }).catch(function(error) {
                        KU.log(error);
                        callback(false, error);
                    });
            }
            else { // system only
                for (var i = 0; i < data.mails.length; i++) {
                    data.mails[i].e2e = true;
//                    data.mails[i].from_f = KU.formatLine(data.mails[i].from, 50);
                    data.mails[i].display_name = data.mails[i].from;
                    data.mails[i].display_name_f = data.mails[i].from;
                    data.mails[i].subject_f = data.mails[i].subject;
                    data.mails[i].body = data.mails[i].mail;
                    data.mails[i].body_preview = $(data.mails[i].mail).text();
                    KRYPTOS.Messages.add(data.mails[i].uuid, data.mails[i]);
                    //KRYPTOS.session.setItem("m" + data.mails[i].uuid, JSON.stringify(data.mails[i]));
                }
                callback(true, data);
            }
        }
        else {
            callback(true, false);
        }
    };

    var showing = function(page) {
        return page === whereAreWe;
    };

    var setKeyStore = function(mailKeyStore) {
        keyStore = mailKeyStore;
    };

    var init = function(mailKeyStore) {
        keyStore = mailKeyStore;
        CD = CommonDashboard;
        window.opener = null;
        $('button#verify-password').prop('disabled', false);
        $('button#confirm-delete').prop('disabled', false);
        //Layout.init();
        if (!hasInit) {
            handleEvents();
            initDatePickers();
            hasInit = true;
        }
//        content = $('#email-container .inbox-content');
    };

    return {

        isChatEnabled: function() {
            return chatEnabled;
        },
        disableChat: function() {
            chatEnabled = false;
        },

        loadInbox: loadInbox,

        forceLoadInbox: forceLoadInbox,

        showing: showing,

        loadMessage: loadMessage,

        compose: compose,

        getMessages: getMessages,

        setKeyStore: setKeyStore,

        sendAutoMail: sendAutoMail,

        checkDraft: checkDraft,

        //main function to initiate the module
        init: init

    };

}();

document.addEventListener("dragstart", function(ev) {
    ev.dataTransfer.setData("text/html", ev.target.id);
    KRYPTOS.Email.dragSourceElement = ev.target;
});

