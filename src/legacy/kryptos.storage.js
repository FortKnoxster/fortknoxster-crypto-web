/* global KRYPTOS, converse, locales, UNKNOWN, Handlebars, showErrorMessage, CommonDashboard, Contacts, Contacts */

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
 * The KRYPTOS Storage Module.
 *
 */
KRYPTOS.Storage = (function() {
  const KU = KRYPTOS.utils

  let keyStore = null

  let hasInit = false

  const uploadQueue = new Queue(5)

  const downloadQueue = new Queue(5)

  const filePartSize = 4194304

  let ghostDrop = null

  let ghostDrop2 = null

  let breadcrumbs = []

  const items = []

  let rootFolder = null

  let currentFolder = null

  let owner = ''

  let storageArea = null

  let storageContent = null

  let storageIntro = null

  const globalCreateDefaultFolders = false

  const defaultFolders = ['Documents', 'Pictures', 'Music', 'Videos']

  const templateStorageItem = Handlebars.templates['storage-item']

  const templateStorageTransferItem =
    Handlebars.templates['storage-transfer-item']

  const templateStorageItemInfo = Handlebars.templates['storage-item-info']

  const templateBreadcrumbs = Handlebars.templates['storage-breadcrumbs']

  const templateStorageFolderTree = Handlebars.templates['storage-folder-tree']

  const templateAcceptShares = Handlebars.templates['accept-shares']

  const templateManageShares = Handlebars.templates['manage-shares']

  const templateManageShareItems = Handlebars.templates['manage-share-items']

  const templateManageShareItemsNotOwner =
    Handlebars.templates['manage-share-items-notowner']

  const emptyFolderMessage =
    Handlebars.templates['storage-empty-folder-message']

  const emailShareFolder = Handlebars.templates['email-share-folder']

  /**
   * Set up new key pairs for storage.
   *
   * @param {function} callback
   * @returns {Promise}
   */
  const setup = function(callback) {
    // Callback required
    CommonDashboard.overlayShow()
    // Create root folder
    const setupData = {}
    encryptNewItemAssignment(
      newDirectory('root'),
      (directory, encryptedKey) => {
        setupData.reference_id = newReferenceId()
        setupData.meta_data = directory
        setupData.encrypted_key = encryptedKey

        return KU.sendData(setupData, 'storage/setup', (success, data) => {
          if (success) {
            decryptItemAssignment(data, root => {
              rootFolder = currentFolder = root
              items[root.item.id] = root

              // globalCreateDefaultFolders = true;
              const promises = []
              for (let i = 0; i < defaultFolders.length; i++) {
                promises.push(
                  new encryptNewFolder(defaultFolders[i], data.item.id),
                )
              }
              // {send_data: sendData, plain_data: plainMetaData, key: key}
              KRYPTOS.Promise.all(promises)
                .then(newItems => {
                  const updateChildren = []
                  const sendData = []
                  for (let i = 0; i < newItems.length; i++) {
                    sendData.push(newItems[i].send_data)
                    updateChildren.push({
                      id: null,
                      key: newItems[i].key,
                      rid: newItems[i].send_data.reference_id,
                      type: newItems[i].send_data.type,
                    })
                  }

                  KRYPTOS.API.addItems({ items: sendData }, addedItems => {
                    // id, key, rid, type
                    for (let i = 0; i < addedItems.length; i++) {
                      items[addedItems[i].item.id] = addedItems[i]
                      items[addedItems[i].item.id].item.plain =
                        newItems[i].plain_data
                      items[addedItems[i].item.id].item.plain_key =
                        newItems[i].key
                      items[addedItems[i].item.id].item.reference_id =
                        addedItems[i].item.reference_id
                      items[addedItems[i].item.id].childs = []

                      updateChildren[i].id = addedItems[i].item.id
                    }
                    addChilds(updateChildren, () => {
                      KRYPTOS.session.setItem('has_storage', 'true')
                      CommonDashboard.overlayHide()
                      callback(true)
                    })
                  })
                })
                .catch(error => {
                  CommonDashboard.overlayHide()
                  callback(false, error)
                })
            })
          } else {
            showErrorMessage('Setup Error!', data.errors)
          }
        })
      },
    )
  }

  const init = function(storageKeyStore, username, skipInit) {
    owner = username
    keyStore = storageKeyStore
    if (skipInit) {
      return
    }
    if (!hasInit) {
      if (initGhostDrop()) {
        hasInit = true
        storageArea = $('.storage-area')
        storageContent = $('#files-container')
        storageIntro = $('#storage-splash')
        breadcrumbs = []
        getRoot()
        getShares()
        getManageShares()
        initCreateFolder()
        initFileUpload()
        initFolderUpload()
        initDeleteItem()
        initMoveItem()
        initCopyItem()
        initShareItem()
        initRenameItem()
        initProperties()
        initActions()
        initGhostDropItems()
        initFolderTree()
        initDeleteUser()
        initLeaveFolder()
      }
    }
  }

  var initGhostDrop = function() {
    ghostDrop = document.getElementById('ghostdrop')
    ghostDrop2 = document.getElementById('drop-file-here')
    if (ghostDrop === null) {
      return false
    }
    ghostDrop.addEventListener('dragenter', dragenter, false)
    ghostDrop.addEventListener('dragleave', dragleave, false)
    ghostDrop.addEventListener('dragover', dragover, false)
    ghostDrop.addEventListener('drop', drop, false)

    //        ghostDrop2.addEventListener("dragenter", function(e) {
    //            e.stopPropagation();
    //            e.preventDefault();
    //            showFiles();
    //        }, false);
    ghostDrop2.addEventListener('dragenter', dragenter, false)
    ghostDrop2.addEventListener('dragleave', dragleave, false)
    ghostDrop2.addEventListener('dragover', dragover, false)
    ghostDrop2.addEventListener('drop', drop, false)

    return true
  }

  var initGhostDropItems = function() {
    storageContent.on('dragstart', '.storage-item, .tree-folder', e => {
      const draggedItemId = $(e.currentTarget).attr('data-item-id')
      e.originalEvent.dataTransfer.setData('text/plain', draggedItemId)
    })

    storageContent.on(
      'dragenter',
      '.storage-item[data-item-type="directory"], .tree-folder-item[data-item-type="directory"]',
      function(e) {
        $(this).addClass('selected')
        e.stopPropagation()
        e.preventDefault()
      },
    )

    storageContent.on(
      'dragleave',
      '.storage-item[data-item-type="directory"], .tree-folder-item[data-item-type="directory"]',
      function(e) {
        $(this).removeClass('selected')
        e.stopPropagation()
        e.preventDefault()
      },
    )

    storageContent.on(
      'dragover',
      '.storage-item[data-item-type="directory"], .tree-folder-item[data-item-type="directory"]',
      function(e) {
        $(this).addClass('selected')
        e.stopPropagation()
        e.preventDefault()
      },
    )

    storageContent.on(
      'drop',
      '.storage-item[data-item-type="directory"], .tree-folder-item[data-item-type="directory"]',
      e => {
        e.stopPropagation()
        e.preventDefault()
        const targetItemId = $(e.currentTarget).attr('data-item-id')
        const dt = e.originalEvent.dataTransfer
        const moveItemId = dt.getData('text/plain')
        if (moveItemId) {
          // Move item to folder
          moveItems(moveItemId, targetItemId)
        } else if (dt.files) {
          // Copy external user files to folder
          openFolder(targetItemId)
          handleFiles(dt.files)
        }
      },
    )
  }

  var drop = function(e) {
    const targetId = $(e.currentTarget).attr('id')
    if (!targetId || targetId !== 'ghostdrop') {
      currentFolder = rootFolder
      showFiles(true)
      handleDrop(e)
    } else {
      handleDrop(e)
    }
  }

  var handleDrop = function(e) {
    e.stopPropagation()
    e.preventDefault()
    const dt = e.dataTransfer
    if (dt.files && dt.files.length > 0) {
      if (dt.items && dt.items.length) {
        // Chrome on Mac fix to avoid folder as file
        for (let i = 0; i < dt.items.length; i++) {
          const entry = dt.items[i].webkitGetAsEntry()
          if (entry === null || entry.isDirectory) {
            showErrorMessage(
              'Folder Upload',
              'Folder upload is currently not supported via drag/drop.',
            )
            return
          }
        }
      }
      handleFiles(dt.files)
    }
  }

  var dragenter = function(e) {
    e.stopPropagation()
    e.preventDefault()
  }

  var dragleave = function(e) {
    e.stopPropagation()
    e.preventDefault()
  }

  var dragover = function(e) {
    e.stopPropagation()
    e.preventDefault()
  }

  var newReferenceId = function() {
    return KU.ab2hex(KRYPTOS.randomValue(32))
  }

  const resetFiles = function() {
    $('#upload-files').val('')
    $('#upload-files').focus()
  }

  // Is folder?
  // Max 10 files
  // Max 100 MB
  // Duplicate? Replace or rename?
  const validateFiles = function(files) {
    // Is folder?
    if (
      files.length === 1 &&
      files[0].type === '' &&
      files[0].size % 4096 === 0
    ) {
      showErrorMessage(
        'Folder Upload',
        'Folder upload is currently not supported via drag/drop.',
      )
      resetFiles()
      return false
    }

    // Max files
    if (files.length > 10) {
      showErrorMessage(
        'Max Files',
        'Maximum 10 files can be uploaded at the same time.',
      )
      resetFiles()
      return false
    }
    // Max size
    let totalSize = 0
    for (var i = 0; i < files.length; i++) {
      totalSize += files[i].size
      if (totalSize > 500000000) {
        showErrorMessage(
          'Max Size Exceeded',
          'One or more files are bigger than max file(s) upload size allowed, 500MB.',
        )
        resetFiles()
        return false
      }
      if (files[i].size <= 0) {
        showErrorMessage('File Empty', 'The file is empty.')
        resetFiles()
        return false
      }
    }
    // Validate file names
    for (var i = 0; i < files.length; i++) {
      if (!validateItemName(files[i].name)) {
        return false
      }
    }

    // Same name detected
    return true
  }

  var handleFiles = function(files) {
    if ((files.length && files.length <= 0) || !validateFiles(files)) {
      return
    }
    const promises = []
    CommonDashboard.overlayShow()

    for (let i = 0; i < files.length; i++) {
      promises.push(addNewFile(files[i], i))
    }

    KRYPTOS.Promise.all(promises)
      .then(result => {
        addChilds(result, () => {
          CommonDashboard.overlayHide()

          // 1. loop result and start file upload ui
          // 2. determine file parts and chunk up
          // 3. encrypt file part
          // 4. upload file part

          for (let i = 0; i < result.length; i++) {
            // UPLOAD START!
            insertFileTransfer(result[i].id, 'upload')

            chunkFile(files[result[i].index], result[i].id, itemId => {})
          }
        })
      })
      .catch(error => {
        CommonDashboard.overlayHide()
        callback(false, error)
      })
  }

  const acceptShare = function(itemId) {
    KRYPTOS.API.acceptShare(itemId, data => {
      getShares()
      showSuccessMessage(
        'Share Accepted',
        "You've successfull accepted a share folder request. The folder is now placed in your Home folder.",
      )
      showFiles(false, itemId)
    })
  }

  const insertAcceptShares = function(shares) {
    const html = templateAcceptShares({ shares })
    $('#accept-shares-page').html(html)
    $('#accept-shares-page .accept-share').one('click', function(e) {
      e.preventDefault()
      // $(this).prop('disabled', true);
      const itemId = $(this).data('share')
      acceptShare(itemId)
    })
    $('#accept-shares-page .reject-share').one('click', function(e) {
      e.preventDefault()
      const sendData = {
        item_id: $(this).data('share'),
        email: owner,
      }
      KRYPTOS.API.unshareItem(sendData, () => {
        getShares()
        reset()
      })
    })
  }

  const insertManageShares = function(shared) {
    const html = templateManageShares({ shared })
    $('#manage-shares-area').html(html)
  }

  var insertFileTransfer = function(itemId, transferType) {
    // Add to transfers
    const item = items[itemId]
    const obj = {
      id: item.item.id,
      type: KU.cleanString(item.item.plain.t, true),
      name: KU.formatLine(
        KU.cleanString(decodeURIComponent(item.item.plain.n)),
        50,
      ),
      size: KU.bytesToSize(item.item.plain.s),
      bytes: KU.cleanString(item.item.plain.s, true),
      part_size: KU.cleanString(item.item.plain.ps, true),
      total_size: KU.cleanString(item.item.plain.s, true),
      icon: mimeTypeToIcon(item.item.plain.mt),
      is_upload: transferType === 'upload',
    }

    const html = templateStorageTransferItem(obj)
    $('.file-transfer-table table tbody.files').append(html)
    showFileTransfer()
    updateFileTransferCount()
  }

  const removeFileTransfer = function(itemId, remove) {
    $(
      `.file-transfer-table table tbody.files tr[data-item-id="${itemId}"]`,
    ).remove()
    updateFileTransferCount()
    if (remove) {
      removeItem(itemId)
    }
  }

  /**
   * Read file input in chunks, encrypt in chunks and push to upload queue.
   *
   * @param {type} file
   * @param {type} itemId
   * @param {type} callback
   * @returns {void}
   */
  var chunkFile = function(file, itemId, callback) {
    const partCount = getPartCount(file.size)
    const fileSize = file.size
    const chunkSize = filePartSize // bytes
    let offset = 0
    let partNumber = 0
    const self = this // we need a reference to the current object
    let block = null

    const handler = function(evt) {
      if (evt.target.error === null) {
        offset += chunkSize
        new KRYPTOS.Encrypter(keyStore, null, null, null).encryptFilePart(
          evt.target.result,
          itemId,
          partNumber,
          result => {
            items[result.id].item.plain.p.push({
              p: result.part, // part

              k: result.key, // key
              iv: result.iv,
              //                        m: result.hmac // mac
            })
            const sendData = []
            sendData.item_id = result.id
            sendData.part_no = result.part
            sendData.data = result.encrypted
            const job = {
              run: uploadFilePart,
              data: sendData,
              queued: false,
              oncompleted(refresh) {
                if (refresh) {
                  uploadQueue.refresh()
                }
              },
              onerror() {},
              onexecuting() {
                ++partNumber
                block(offset, chunkSize, file)
              },
            }

            uploadQueue.push(job)
          },
        )
      } else {
        return
      }
      if (offset > fileSize) {
        callback(itemId)
      }
    }

    block = function(_offset, length, _file) {
      if (offset < fileSize) {
        const end = length + _offset
        const r = new FileReader()
        const blob = _file.slice(_offset, length + _offset)
        r.onload = handler
        r.readAsArrayBuffer(blob)
      } else {
        callback()
      }
    }

    block(offset, chunkSize, file)
  }

  const hasUploaded = function(itemId) {
    return (
      items[itemId] &&
      items[itemId].item.plain.p.length * items[itemId].item.plain.ps >=
        items[itemId].item.plain.s
    )
  }

  /**
   * Download a file in parts, push to the download queue, decrypt file part.
   * Join file parts when synchronized promises.
   *
   * @param {type} itemId
   * @returns {undefined}
   */
  const downloadFile = function(itemId) {
    const uploaded = hasUploaded(itemId)
    if (!uploaded && !items[itemId].item.is_owner) {
      showErrorMessage(
        'Download Error',
        'The file is still synchronizing, please wait...',
      )
      return
    }
    if (!uploaded && items[itemId].item.is_owner) {
      showErrorMessage(
        'Download Error',
        "The file upload wasn't completed. Please delete it and upload it again.",
      )
      return
    }
    const promises = []
    insertFileTransfer(itemId, 'download')
    for (let i = 0; i < items[itemId].item.plain.p.length; i++) {
      var part = items[itemId].item.plain.p[i]

      promises.push(
        new KRYPTOS.Promise((resolve, reject) => {
          const job = {
            run: getFileChunk,
            data: {
              item_id: itemId,
              part: part.p,
              key: part.k,
              iv: part.iv,
              // mac: part.m
            },
            queued: false,
            oncompleted(refresh, result) {
              if (refresh) {
                downloadQueue.refresh()
              }
              resolve({
                id: result.id,
                part: result.part,
                file: result.file,
                // url: URL.createObjectURL(new Blob([result.file], {type: "application/octet-stream"}))
              })
            },
            onerror() {},
            onexecuting() {
              downloadQueue.refresh()
            },
          }

          downloadQueue.push(job)
        }),
      )
    }

    KRYPTOS.Promise.all(promises)
      .then(fileParts => {
        if (fileParts.length > 0) {
          const blobs = [fileParts.length]
          for (let i = 0; i < fileParts.length; i++) {
            blobs[i] = fileParts[i].file
          }
          saveAs(
            new Blob(blobs, { type: items[fileParts[0].id].item.plain.mt }),
            decodeURIComponent(items[fileParts[0].id].item.plain.n),
          )
          $(
            `.file-transfer-table table tbody.files tr[data-item-id="${
              fileParts[0].id
            }"]`,
          ).remove()
          updateFileTransferCount()
          // Cleanup
          //                for (var i = 0; i < blobs.length; i++) {
          //                    blobs[i] = null;
          //                }
          //                blobs = null;
        }
      })
      .catch(error => {
        // callback(false, error);
      })
  }

  const isUploading = function(itemId) {
    return (
      $(`.file-transfer-table table tbody.files tr[data-item-id="${itemId}"]`)
        .length > 0
    )
  }

  // Called from download queue
  var getFileChunk = function(data, callback) {
    const transfer = $(
      `.file-transfer-table table tbody.files tr[data-item-id="${
        data.item_id
      }"]`,
    )
    let lastLoaded = 0
    KRYPTOS.API.downloadItem(
      data.item_id,
      data.part,
      (filePart, removeItem) => {
        if (filePart === false) {
          removeFileTransfer(data.item_id, removeItem)
          return
        }
        new KRYPTOS.Decrypter(
          keyStore,
          KU.b642ab(data.key),
          KU.b642ab(data.iv),
          filePart,
          null,
          null,
          null,
          callback,
        ).decryptFilePart(data.item_id, data.part)
      },
      e => {
        const loaded = e.loaded - lastLoaded
        const bytesTransfered =
          loaded + parseInt(transfer.attr('data-item-bytes-transfered'))
        const totalBytes = parseInt(transfer.attr('data-item-total-size'))
        transfer.attr('data-item-bytes-transfered', bytesTransfered)
        let percent = Math.round((bytesTransfered / totalBytes) * 100)
        if (percent > 100) {
          percent = 100
        }
        transfer.find('.progress-bar').attr('style', `width:${percent}%`)
        transfer.find('.progress-percent').html(`${percent}%`)
        lastLoaded = e.loaded
      },
    )
  }

  // Called from upload queue
  var uploadFilePart = function(sendData, callback) {
    const transfer = $(
      `.file-transfer-table table tbody.files tr[data-item-id="${
        sendData.item_id
      }"]`,
    )
    let lastLoaded = 0
    KU.sendData(
      sendData,
      'storage/upload-item',
      (success, response) => {
        if (success === false) {
          KU.error(showErrorMessage, 'Upload Error', response)
          // showErrorMessage("Upload Error", "Something went wrong uploading the encrypted file part!");
          transfer.remove()
          updateFileTransferCount()
          if (callback) {
            callback(false)
          }
        } else {
          // Upload done!
          items[sendData.item_id].uploads = items[sendData.item_id].uploads
            ? ++items[sendData.item_id].uploads
            : 1
          if (
            items[sendData.item_id].uploads ===
            getPartCount(items[sendData.item_id].item.plain.s)
          ) {
            keyStore.setCachePsk(true)
            updateItem(items[sendData.item_id], () => {
              transfer.remove()
              updateFileTransferCount()
            })
          }
          callback()
        }
      },
      e => {
        if (e.lengthComputable) {
          const loaded = e.loaded - lastLoaded
          const bytesTransfered =
            loaded + parseInt(transfer.attr('data-item-bytes-transfered'))
          const totalBytes = parseInt(transfer.attr('data-item-total-size'))
          transfer.attr('data-item-bytes-transfered', bytesTransfered)
          let percent = Math.round((bytesTransfered / totalBytes) * 100)
          if (percent > 100) {
            percent = 100
          }
          transfer.find('.progress-bar').attr('style', `width:${percent}%`)
          transfer.find('.progress-percent').html(`${percent}%`)
          lastLoaded = e.loaded
        }
      },
    )
  }

  var getPartCount = function(size) {
    return Math.ceil(size / filePartSize)
  }

  // API
  var addNewFile = function(file, index) {
    return new KRYPTOS.Promise((resolve, reject) => {
      const fileMetaData = newFile(file)
      const plainMetaData = fileMetaData.d
      encryptNewItem(fileMetaData, (metaData, key) => {
        const referenceId = newReferenceId()
        const sendData = {
          parent_id: currentFolderId(),
          reference_id: referenceId,
          type: 'file',
          meta_data: metaData,
          part_count: getPartCount(plainMetaData.s),
        }
        KRYPTOS.API.addItem(sendData, result => {
          items[result.item.id] = result
          items[result.item.id].item.plain = plainMetaData
          items[result.item.id].item.plain_key = key
          items[result.item.id].item.reference_id = referenceId
          items[result.item.id].childs = []
          insertItem({ id: result.item.id, plain: plainMetaData })
          resolve({
            id: result.item.id,
            rid: referenceId,
            key,
            index,
            type: 'file',
          })
        })
      })
    })
  }

  const hasChildFolders = function(itemId) {
    if (items[itemId]) {
      if (KU.isEmpty(items[itemId].item.plain.ch)) {
        return false
      }
      for (let i = 0; i < items[itemId].item.plain.ch.length; i++) {
        if (items[itemId].item.plain.ch[i].t === 'directory') {
          return true
        }
      }
      return false
    }
    return false
  }

  var initFolderTree = function() {
    $('.css-treeview').on('click', 'div.tree-folder-item', function(e) {
      e.preventDefault()
      const type = $(this)
        .closest('.css-treeview')
        .attr('data-type')
      const popup = $(`#${type}-item-popup`)
      popup.find('div.tree-folder-item').removeClass('selected')
      popup.attr('data-selected-item-id', '')
      const itemId = $(this)
        .find('input')
        .attr('data-item-id')
      popup.attr('data-selected-item-id', itemId)
      $(this).addClass('selected')
      if (hasChildFolders(itemId)) {
        if (rootFolder.item.id === itemId) {
          if (type === 'menu') {
            openFolder(itemId)
          }
          return
        } // Don't close root folder
        if ($(this).next().length > 0) {
          // is open, remove childs and close
          $(this)
            .next()
            .remove()
          $(this)
            .find('label i.fa-caret-down')
            .addClass('fa-caret-right')
            .removeClass('fa-caret-down')
          $(this)
            .find('label i.fa-folder-open')
            .addClass('fa-folder')
            .removeClass('fa-folder-open')
          return
        }
        // not open, show childs and open
        $(this)
          .find('label i.fa-caret-right')
          .addClass('fa-caret-down')
          .removeClass('fa-caret-right')
        $(this)
          .find('label i.fa-folder')
          .addClass('fa-folder-open')
          .removeClass('fa-folder')
        showFolderTree(type, itemId)
      }
      if (type === 'menu') {
        openFolder(itemId)
      }
    })
  }

  var showFolderTree = function(view, parentId, initial, skip) {
    const tree = $(`#${view}-tree-view`)
    const treeItems = { items: [] }

    if (parentId) {
      const queryId = `${parentId}${items[parentId].item.parent_id || ''}`
      tree
        .find(`li.tree-folder div[id="item_id_${queryId}"]`)
        .next()
        .remove()
      // Check if children was added already
      const len = tree
        .find(`li.tree-folder div[id="item_id_${queryId}"]`)
        .next().length
      if (len > 0) {
        return
      }
    } else {
      // root
      parentId = rootFolder.item.id
      treeItems.items.push({
        id: items[parentId].item.id,
        parent_id: items[parentId].item.parent_id,
        name: 'Home',
        has_children: hasChildFolders(items[parentId].item.id),
        is_open: true,
        type: items[parentId].item.type,
      })

      tree.html(templateStorageFolderTree(treeItems))
    }

    if (initial) {
      return
    }
    if (skip) {
      insertFolderTree(tree, parentId)
    } else {
      getChildFolders(parentId, result => {
        insertFolderTree(tree, parentId)
      })
    }
  }

  var insertFolderTree = function(tree, parentId) {
    const treeItems = { items: [] }
    for (let i = 0; i < items[parentId].childs.length; i++) {
      if (
        items[parentId].childs[i].type === 'directory' &&
        items[items[parentId].childs[i].id] &&
        items[items[parentId].childs[i].id].item.plain
      ) {
        const fullName = KU.cleanString(
          decodeURIComponent(items[items[parentId].childs[i].id].item.plain.n),
        )
        treeItems.items.push({
          id: items[parentId].childs[i].id,
          parent_id: items[parentId].childs[i].parent_id,
          name: KU.formatLine(fullName, 15),
          full_name: fullName,
          has_children: hasChildFolders(items[parentId].childs[i].id),
          is_open: false,
          is_owner: items[parentId].childs[i].is_owner,
          is_shared: items[parentId].childs[i].is_shared,
          type: items[parentId].childs[i].type,
        })
      }
    }
    if (!KU.isEmpty(treeItems.items)) {
      const queryId = `${parentId}${items[parentId].item.parent_id || ''}`
      tree
        .find(`li.tree-folder div[id="item_id_${queryId}"]`)
        .after(templateStorageFolderTree(treeItems))
      const menu = tree
        .find(`li.tree-folder div[id="item_id_${queryId}"]`)
        .next()
      // Alphabetical order please
      const menuli = menu.children('li')
      menuli.sort((a, b) => {
        const ac = a.getAttribute('data-name')
        const bc = b.getAttribute('data-name')
        return ac.localeCompare(bc)
      })
      menuli.detach().appendTo(menu)
    }
  }

  const showBreadcrumbs = function(itemId) {
    const breadcrumbsItems = {
      root_id: rootFolder.item.id,
      breadcrumbs: [],
    }
    if (itemId && itemId !== rootFolder.item.id) {
      let item = items[itemId]
      do {
        breadcrumbsItems.breadcrumbs.unshift({
          id: item.item.id,
          name: decodeURIComponent(item.item.plain.n),
        })
        if (item.item.parent_id === rootFolder.item.id) {
          item = null
          break
        }
        item = item.item.parent_id === null ? null : items[item.item.parent_id]
      } while (item !== null)
    }

    const html = templateBreadcrumbs(breadcrumbsItems)
    $('#breadcrumbs').html(html)
  }

  var newDirectory = function(name) {
    return {
      s: null, // signature
      so: owner, // signature_owner
      iv: null,
      v: 1, // version
      d: {
        t: 'directory', // type
        n: encodeURIComponent(name), // name
        c: new Date().getTime(), // created
        m: new Date().getTime(), // modified
        ch: [], // childs
      },
    }
  }

  var newFile = function(file) {
    return {
      s: null, // signature
      so: owner, // signature_owner
      iv: null,
      v: 1, // version
      d: {
        t: 'file', // type
        n: encodeURIComponent(file.name), // name
        c: new Date().getTime(), // created
        m: file.modified || new Date().getTime(), // modified
        s: file.size, // size
        mt: file.type, // mimetype
        ps: filePartSize, // partsize
        p: [], // parts
      },
    }
  }

  var encryptNewItemAssignment = function(item, callback) {
    const Encrypter = new KRYPTOS.Encrypter(
      keyStore,
      item.d,
      null,
      (success, result) => {
        if (success) {
          item.s = result.signature
          item.so = owner
          item.iv = result.iv
          item.d = result.message
          callback(JSON.stringify(item), result.encrypted_key)
        } else {
        }
      },
    )
    Encrypter.encryptNewItemAssignment()
  }

  const encryptItemAssignment = function(key, recipients, callback) {
    const Encrypter = new KRYPTOS.Encrypter(
      keyStore,
      '',
      recipients,
      (success, result) => {
        if (success) {
          callback(result)
        } else {
        }
      },
    )
    Encrypter.encryptItemAssignment(KU.b642ab(key))
  }

  var encryptNewItem = function(item, callback) {
    const Encrypter = new KRYPTOS.Encrypter(
      keyStore,
      item.d,
      null,
      (success, result) => {
        if (success) {
          item.s = result.signature
          item.so = owner
          item.iv = result.iv
          item.d = result.message
          callback(JSON.stringify(item), result.key)
        } else {
        }
      },
    )
    Encrypter.encryptNewItem()
  }

  const encryptExistingItem = function(directoryData, key, iv, callback) {
    const Encrypter = new KRYPTOS.Encrypter(
      keyStore,
      directoryData,
      null,
      (success, result) => {
        if (success) {
          callback(result)
        } else {
        }
      },
    )
    Encrypter.encryptExistingItem(KU.b642ab(key), new Uint8Array(KU.b642ab(iv)))
  }

  const decryptItem = function(json, id, rid, key, callback) {
    const metaData = JSON.parse(json)
    if (owner === metaData.so) {
      decryptItemMetadata(
        metaData,
        id,
        rid,
        key,
        keyStore.getPvk(true),
        callback,
      )
    } else {
      keyStore.getPublicKey(metaData.so, 'verify', pvk => {
        decryptItemMetadata(metaData, id, rid, key, pvk, callback)
      })
    }
  }

  var decryptItemMetadata = function(metaData, id, rid, key, pvk, callback) {
    const Decrypter = new KRYPTOS.Decrypter(
      keyStore,
      KU.b642ab(key),
      new Uint8Array(KU.b642ab(metaData.iv)),
      KU.b642ab(metaData.d),
      KU.b642ab(metaData.s),
      pvk,
      null,
      (result, error) => {
        if (result === false) {
          showErrorMessage('Some Error!', error)
        } else {
          callback(result)
        }
      },
    )
    Decrypter.decryptItem(id, rid)
  }

  var decryptItemAssignment = function(data, callback) {
    const metaData = JSON.parse(data.item.meta_data)
    //        keyStore.getPdk(function(success, pdk) {
    //            if (success) {
    //                var user = metaData.so !== owner ? metaData.so : owner;

    if (owner === metaData.so) {
      decryptItemAssignmentMetadata(data, keyStore.getPvk(true), callback)
    } else {
      keyStore.getPublicKey(metaData.so, 'verify', pvk => {
        decryptItemAssignmentMetadata(data, pvk, callback)
      })
    }

    //            } // end if (success) {
    //            else {
    //                showErrorMessage("Some Error!", pdk);
    //            }
    //        }); // end keyStore.getPdk
  }

  var decryptItemAssignmentMetadata = function(data, pvk, callback) {
    const metaData = JSON.parse(data.item.meta_data)
    const Decrypter = new KRYPTOS.Decrypter(
      keyStore,
      KU.b642ab(data.item_key),
      new Uint8Array(KU.b642ab(metaData.iv)),
      KU.b642ab(metaData.d),
      KU.b642ab(metaData.s),
      pvk,
      null,
      (result, error) => {
        if (result === false) {
          showErrorMessage('Some Error!', error)
        } else {
          data.item.plain = result.json
          data.item.plain_key = result.key
          callback(data)
        }
      },
    ) // end var Decrypter

    Decrypter.decryptItemAssignment()
  }

  // API
  const getItem = function(itemId, reload) {
    if (
      !reload &&
      !KU.isEmpty(currentFolder.childs) &&
      currentFolder.childs.length === currentFolder.item.plain.ch.length
    ) {
      getChildren()
    } else {
      CommonDashboard.overlayShow()
      KRYPTOS.API.getItem(itemId, data => {
        if (data.childs && !KU.isEmpty(data.childs)) {
          CF().childs = data.childs
          if (reload && items[itemId].item.plain_key !== null) {
            decryptItem(
              data.item.meta_data,
              itemId,
              items[itemId].item.reference_id,
              items[itemId].item.plain_key,
              result => {
                items[result.id].item.owner = data.item.owner
                items[result.id].childs = data.childs
                items[result.id].item.plain = result.plain
                // items[result.id].item.plain.n = items[result.id].item.plain.n;
                items[result.id].item.meta_data = data.item.meta_data
                getChildren()
              },
            )
          } else {
            getChildren()
          }
        } else {
          storageArea.html(emptyFolderMessage({}))
        }
        CommonDashboard.overlayHide()
      })
    }
  }

  // API
  var getRoot = function(openItemId) {
    //        var localCreateDefaultFolders
    KRYPTOS.API.getRoot(data => {
      //            if (data.root.childs.length === 0) {
      //                createDefaultFolders = true;
      //            }
      keyStore.setPublicKeys(data.public_keys)
      decryptItemAssignment(data.root, root => {
        rootFolder = currentFolder = root
        showBreadcrumbs()
        items[root.item.id] = root
        if (!openItemId) {
          CommonDashboard.overlayHide()
        }
        if (data.root.shares) {
          getSharz(data.root.shares, root.item.id, openItemId)
        }

        getChildren()
        //                if (globalCreateDefaultFolders) {
        //                    globalCreateDefaultFolders = false;
        //                    createDefaultFolderPromisified('Documents')
        //                      .then(createDefaultFolderPromisified('Pictures'))
        //                      .then(createDefaultFolderPromisified('Videos'))
        //                      .then(createDefaultFolderPromisified('Music'));
        // //                    createNewFolder('Documents');
        // //                    createNewFolder('Pictures');
        // //                    createNewFolder('Videos');
        // //                    createNewFolder('Music');
        //                }

        showFolderTree('menu', null, true)

        if (storageArea.is(':empty')) {
          storageArea.html(emptyFolderMessage({}))
        }

        //                if (callback) {
        //                    callback();
        //                }
      })
    })
  }

  const createDefaultFolderPromisified = function(name) {
    return new Promise((res, rej) => {
      createNewFolder(name)
      res(name)
    })
  }

  var reset = function(clearOnly, openItemId) {
    CommonDashboard.overlayShow()
    breadcrumbs = []
    currentFolder = rootFolder
    storageArea.html('')
    if (!clearOnly) {
      getRoot(openItemId)
    } else {
      CommonDashboard.overlayHide()
    }
  }

  var getSharz = function(shares, rootId, openItemId) {
    for (let i = 0; i < shares.length; i++) {
      decryptItemAssignment(shares[i], shareItem => {
        shareItem.item.parent_id = rootId
        // shareItem.item.is_shared = true;
        items[shareItem.item.id] = shareItem
        currentFolder.childs.push(shareItem.item)
        insertItem(shareItem.item, true)
        if (openItemId && openItemId === shareItem.item.id) {
          openFolder(openItemId)
        }
        // showFolderTree('menu', null, true, true);
        // addChild(shareItem.item.id, shareItem.item_key, shareItem.item.type);
      })
    }
    // showFolderTree('menu', null, true);
    // getChildren();
    // updateCurrentFolder();
  }

  // API
  var getManageShares = function() {
    KRYPTOS.API.getManageShares(data => {
      insertManageShares(data)
    })
  }

  // API
  var getShares = function() {
    KRYPTOS.API.getShares(data => {
      const numShares = Object.keys(data).length
      if (numShares) {
        $('#share-menu').show()
        insertAcceptShares(data)
        $('.new-shares')
          .html(numShares)
          .show()
      } else {
        $('#share-menu').hide()
        $('#accept-shares-page').hide()
        $('.new-shares')
          .html('')
          .hide()
      }
    })
  }

  var getChildren = function(fromCache) {
    storageArea.html('')
    for (let i = 0; i < CF().childs.length; i++) {
      // from cache
      if (
        fromCache &&
        items[CF().childs[i].id] &&
        items[CF().childs[i].id].item.plain
      ) {
        insertItem(items[CF().childs[i].id].item, true)
      } else {
        for (let j = 0; j < CF().item.plain.ch.length; j++) {
          // If uploading, skip local item update and just insert to view
          if (isUploading(CF().childs[i].id)) {
            insertItem(items[CF().childs[i].id].item, true)
          } else if (
            CF().item.plain.ch[j].r === CF().childs[i].reference_id &&
            !isUploading(CF().childs[i].id)
          ) {
            items[CF().childs[i].id] = {
              childs: [],
              item: CF().childs[i],
              item_key: null,
              parent: null,
            }
            items[CF().childs[i].id].item.plain_key = CF().item.plain.ch[j].k
            items[CF().childs[i].id].item.item_members = CF().item.item_members
            // items[CF().childs[i].id].item.owner = CF().item.owner;
            decryptItem(
              CF().childs[i].meta_data,
              CF().childs[i].id,
              CF().childs[i].reference_id,
              CF().item.plain.ch[j].k,
              result => {
                items[result.id].item.plain = result.plain
                // items[result.id].item.plain.n = decodeURIComponent(items[result.id].item.plain.n);
                insertItem(items[result.id].item, true)
              },
            )
            break
          }
        }
      }
    }
  }

  var getChildFolders = function(parentId, callback) {
    if (
      !KU.isEmpty(items[parentId].item.plain.ch) &&
      (items[parentId].childs.length !== 0 &&
        items[parentId].item.plain.ch.length !== 0)
    ) {
      callback(false)
    } else {
      CommonDashboard.overlayShow()
      KRYPTOS.API.getItem(parentId, data => {
        items[parentId].childs = data.childs
        const promises = []

        for (var i = 0; i < items[parentId].childs.length; i++) {
          for (var j = 0; j < items[parentId].item.plain.ch.length; j++) {
            if (
              items[parentId].item.plain.ch[j].r ===
              items[parentId].childs[i].reference_id
            ) {
              items[items[parentId].childs[i].id] = {
                childs: [],
                item: items[parentId].childs[i],
                item_key: null,
                parent: null,
              }
              items[items[parentId].childs[i].id].item.plain_key =
                items[parentId].item.plain.ch[j].k

              promises.push(
                new KRYPTOS.Promise((resolve, reject) => {
                  decryptItem(
                    items[parentId].childs[i].meta_data,
                    items[parentId].childs[i].id,
                    items[parentId].childs[i].reference_id,
                    items[parentId].item.plain.ch[j].k,
                    result => {
                      items[result.id].item.plain = result.plain
                      resolve({})
                      // insertItem(result);
                    },
                  )
                }),
              )

              break
            }
          }
        }

        KRYPTOS.Promise.all(promises)
          .then(result => {
            CommonDashboard.overlayHide()
            callback(true)
          })
          .catch(error => {
            CommonDashboard.overlayHide()
            // callback(false, error);
          })
      })
    }
  }

  var removeItem = function(itemId) {
    $(`.storage-item[data-item-id='${itemId}']`).remove()
    if ($('.storage-item').length === 0) {
      storageArea.html(emptyFolderMessage({}))
    }
  }

  const refreshItem = function(item) {
    removeItem(item.item.id)
    insertItem(item.item)
  }

  var insertItem = function(item, menu) {
    if (item.type === 'file' && !hasUploaded(item.id) && item.owner !== owner) {
      return
    }

    const plainName = KU.cleanString(decodeURIComponent(item.plain.n))
    const obj = {
      id: item.id,
      plain: {
        n: plainName,
        t: KU.cleanString(item.plain.t),
      },
      icon:
        item.plain.t === 'directory'
          ? 'fa-folder'
          : mimeTypeToIcon(item.plain.mt),
      size: KU.bytesToSize(
        item.type === 'directory'
          ? item.cache_item_size_recursive
            ? item.cache_item_size_recursive
            : 0
          : item.plain.s,
      ),
      created: item.plain.c === null ? '' : KU.localDateTime(item.plain.c),
      is_owner: item.is_owner,
      owner: item.owner,
      is_shared: item.is_shared,
    }
    //        item.plain.pn = plainName;
    //        item.plain.t = KU.cleanString(item.plain.t);
    // item.icon = item.plain.t === 'directory' ? 'fa-folder' : mimeTypeToIcon(item.plain.mt);
    //        item.size = KU.bytesToSize((item.type === 'directory' ? (item.cache_item_size_recursive ? item.cache_item_size_recursive : 0) : item.plain.s));
    //        item.created = item.plain.c === null ? "" : KU.localDateTime(item.plain.c);
    if (menu) {
      showFolderTree('menu', item.parent_id, false, true)
    }
    $('#stormessage').remove()
    const html = templateStorageItem(obj)
    const len = $('.storage-item').length
    if (len === 0) {
      $(html)
        .appendTo(storageArea)
        .show()
    } else {
      $('.storage-item').each(function(index) {
        const type = $(this).attr('data-item-type')
        const name = $(this).attr('title')
        let compare = null
        if (item.plain.t === 'directory') {
          if (type !== 'directory') {
            // before files
            $(this)
              .before(html)
              .show()
            return false
          }
          compare = plainName.localeCompare(name)
          if (compare !== 1) {
            $(this)
              .before(html)
              .show()
            return false
          }
        } else if (item.plain.t === 'file') {
          if (type === 'file') {
            compare = plainName.localeCompare(name)
            if (compare !== 1) {
              $(this)
                .before(html)
                .show()
              return false
            }
          }
        }
        if (index === len - 1) {
          // last iteration
          $(this)
            .after(html)
            .show()
        }
      })
    }
    if ($('.context-menu').hasClass('listing'))
      $('.storage .storage-item')
        .removeClass('folder-view')
        .addClass('list-view')
  }

  var initMoveItem = function() {
    $('.move-item').on('click', function() {
      $('#move-item-popup').attr('data-item-id', '')
      $('#move-item-popup').attr('data-item-id', getItemId(this))
      $('#move-item-popup').modal({
        keyboard: true,
        show: true,
      })
      showFolderTree('move')
    })
    $('#move-item-popup button#confirm-move-item').on('click', () => {
      const popup = $('#move-item-popup')
      const newParentId = popup.attr('data-selected-item-id')
      const itemId = popup.attr('data-item-id')
      if (itemId) {
        moveItems(itemId, newParentId)
      }
      $('#confirm-move-item').modal('hide')
      popup.attr('data-selected-item-id', '')
      popup.attr('data-item-id', '')
    })
  }

  var initRenameItem = function() {
    $('.rename-item').on('click', function() {
      $('#rename-item-popup').on('shown.bs.modal', e => {
        $('#rename-item-popup #rename-item').focus()
      })
      const itemId = getItemId(this)
      $('#rename-item-popup').attr('data-item-id', '')
      $('#rename-item-popup input#rename-item').val('')
      $('#rename-item-popup').attr('data-item-id', itemId)
      const title =
        items[itemId].item.plain.t === 'directory'
          ? 'Rename Folder'
          : 'Rename File'
      $('#rename-item-popup .modal-title').text(title)
      $('input#rename-item').val(
        KU.cleanString(decodeURIComponent(items[itemId].item.plain.n)),
      )
      $('#rename-item-popup').modal({
        keyboard: true,
        show: true,
      })
    })
    $('button#rename-item-button').on('click', () => {
      const popup = $('#rename-item-popup')
      const itemId = popup.attr('data-item-id')
      const itemName = $('input#rename-item').val()
      if (validateItemName(itemName)) {
        $('#rename-item-popup').modal('hide')
        popup.attr('data-item-id', '')
        $('input#rename-item').val('')
        renameItem(itemId, itemName)
      }
    })
  }

  const tagitBeforeHelper = function(event, ui, selector) {
    if (!ui.duringInitialization) {
      const tagArray = ui.tagLabel.split(/[,|;]+/)
      if (tagArray.length > 1) {
        for (let i = 0, max = tagArray.length; i < max; i++) {
          // var tEmail = tagArray[i].indexOf("@") === -1 ? KU.u2e(tagArray[i]) : tagArray[i];
          selector.tagit('createTag', tagArray[i])
        }
        return false
      }
      if (ui.tagLabel.indexOf('@') === -1) {
        // selector.tagit("createTag", KU.u2e(ui.tagLabel));
        return false
      }

      const FullName = ui.tagLabel
      const Name = KU.extractDisplayNameFromFullName(ui.tagLabel)
      let Email = false
      if (!Name) {
        if (KU.isItAnEmail(ui.tagLabel)) Email = ui.tagLabel
      } else {
        Email = KU.extractEmailFromFullName(ui.tagLabel)
      }
      ui.tag[0].setAttribute('title', FullName)
      if (Name) {
        ui.tag[0].firstChild.textContent = Name
      } else {
        ui.tag[0].firstChild.textContent = Email
      }
      ui.tag[0].setAttribute('data-email', FullName)
    }
  }

  const tagitAfterHelper = function(event, ui, selector) {
    $('i.epadlock')
      .addClass('fa-lock-alt')
      .css('color', '#3B4D64')
      .attr('title', 'Encrypted')
  }

  const tagitTagSource = function(
    search,
    showChoices,
    availableTags,
    tagitObject,
  ) {
    const filter = search.term.toLowerCase()
    const choices = $.grep(
      availableTags,
      element => element.toLowerCase().match(filter) !== null,
    )
    showChoices(tagitObject._subtractArray(choices, tagitObject.assignedTags()))
    // showChoices(choices);
  }

  const initTagit = function() {
    $('#item-shares').tagit({
      availableTags: Contacts.getFormattedContacts(),
      singleField: true,
      caseSensitive: false,
      allowSpaces: true,
      autocomplete: { delay: 0, minLength: 2 },
      removeConfirmation: true,
      tagSource(search, showChoices) {
        tagitTagSource(search, showChoices, this.options.availableTags, this)
      },
      beforeTagAdded(event, ui) {
        return tagitBeforeHelper(event, ui, $('#item-shares'))
      },
      afterTagAdded(event, ui) {
        return tagitAfterHelper(event, ui, $('#item-shares'))
      },
      beforeTagRemoved(event, ui) {
        const rem = ui.tag[0].title
        $(`li[title="${rem}"] span.tagit-label`).text(rem)
      },
    })
  }

  var initShareItem = function() {
    storageContent.on('click', '.accept-shares', () => {
      // loadPage($(this), 'accept-shares', 'Accept Shares', 'storage');
      $('#accept-shares-page').slideToggle()
    })
    $('.share-item').on('click', function() {
      let itemId = getItemId(this)
      if (!itemId) {
        itemId = currentFolderId()
      }
      const item = items[itemId]
      const isOwner = item.item.is_owner
      if (isOwner) {
        $('#share-item-popup .modal-title').html(
          `Manage Share: ${KU.formatLine(
            KU.cleanString(decodeURIComponent(item.item.plain.n)),
            25,
          )}`,
        ) // KU.formatLine(KU.cleanString(decodeURIComponent(item.item.plain.n)), 50)
        $('#share-item-popup').attr('data-item-id', '')
        $('#share-item-popup').attr('data-item-id', item.item.id)
        $('#share-item-popup').modal({
          keyboard: true,
          show: true,
        })

        $('#share-item-popup').on('shown.bs.modal', e => {
          const tagItInput = $('.tagit-new').find("input[type='text']")
          tagItInput.val('')

          initTagit()
          KRYPTOS.API.getManageShare(item.item.id, shared => {
            // Format share usernames
            for (const share in shared) {
              for (const user in shared[share].users) {
                shared[share].users[user].display_name = KU.formatLine(
                  shared[share].users[user].display_name,
                  25,
                )
              }
            }

            const html = templateManageShareItems({ shared })
            $('#manage-share-items').html(html)
            $('#share-owner').html(
              `Share owner: ${KU.getDisplayNameByUsername(item.item.owner)}`,
            )
            $('select.update-share-item').on('change', function() {
              const select = $(this)
              select.prop('disabled', 'disabled')
              const popup = $('#share-item-popup')
              const itemId = popup.attr('data-item-id')
              if (itemId) {
                const ctxt = $(this)
                  .parent()
                  .parent()
                const user = ctxt.data('user-row')
                const role = ctxt.find('select.share-role').val()
                updateShareItem(itemId, user, role, () => {
                  showSuccessMessage(
                    'Update Successful',
                    "The user's permissions were updated successfully.",
                  )
                  select.prop('disabled', false)
                })
              }
            })
            // WAS HERE DELETE USER
          })
          $('input.ui-autocomplete-input').focus()
        })
      } else {
        $('#share-item-popup-notowner').attr('data-item-id', '')
        $('#share-item-popup-notowner').attr('data-item-id', item.item.id)
        $('#share-item-popup-notowner').modal({
          keyboard: true,
          show: true,
        })
        $('#share-item-popup-notowner').on('shown.bs.modal', e => {
          KRYPTOS.API.getManageShare(item.item.id, shared => {
            const html = templateManageShareItemsNotOwner({ shared })
            $('#manage-share-items-notowner').html(html)
            $('#share-owner-no').html(
              `Share owner: ${KU.getDisplayNameByUsername(item.item.owner)}`,
            )

            // WAS here 2
          })
        })
      }
    })

    $('button#share-item-close').on('click', e => {
      $('#item-shares').tagit('removeAll')
      $('#manage-share-items').html('')
    })

    $('button#share-item-button').on('click', () => {
      const popup = $('#share-item-popup')
      const itemId = popup.attr('data-item-id')
      if (itemId) {
        const users = $('#item-shares').val()

        if (users === '') {
          showErrorMessage(
            'Missing User',
            'Specify at least one user you wish to share with.',
          )
        } else {
          const displayNames = users.split(',')
          const temp = []
          for (let i = 0; i < displayNames.length; i++) {
            const email = KU.extractEmailFromFullName(displayNames[i])
            temp.push(email)
          }
          if (temp.length === 0) {
            showErrorMessage(
              'Missing User',
              'Specify at least one user you wish to share with.',
            )
            return
          }
          const emails = temp.join(',')
          const role = $('#share-role').val()
          shareItem(itemId, emails, role, () => {
            $('#share-item-popup').modal('hide')
            popup.attr('data-selected-item-id', '')
            popup.attr('data-item-id', '')

            // Send email to recipients
            const recipients = {
              to: [],
              cc: [],
              bcc: displayNames,
              from: [CommonDashboard.getUsername()],
            }
            const data = {
              email: CommonDashboard.getUsername(),
              display_name: KU.getDisplayNameById(CommonDashboard.getUserId()),
              item_id: itemId,
              folder: KU.cleanString(
                decodeURIComponent(items[itemId].item.plain.n),
              ),
              company_name: KRYPTOS.session.getItem('company_name'),
            }
            const html = emailShareFolder(data)
            KRYPTOS.Email.sendAutoMail(
              'New Folder Share',
              temp,
              recipients,
              html,
            )
            showSuccessMessage(
              'Folder Shared',
              "You've successfull shared this folder. A notification email has been sent to the user(s) you shared with.",
            )
            $('#share-tree-item-popup').modal('hide')
            $('#item-shares').tagit('removeAll')
            $('#manage-share-items').html('')
          })
        }
      }
    })

    $('#confirm-share-tree-item').on('click', share => {
      share.stopPropagation()
      share.preventDefault()

      const popup = $('#share-tree-item-popup')
      const itemId = popup.attr('data-selected-item-id')
      if (itemId == '') {
        showErrorMessage('Share Folder', 'You must choose a folder to share!')
        return
      }

      const item = items[itemId]
      const isOwner = item.item.is_owner

      if (isOwner) {
        $('#share-item-popup .modal-title').html(
          `Manage Share: ${KU.formatLine(
            KU.cleanString(decodeURIComponent(item.item.plain.n)),
            30,
          )}`,
        )
        $('#share-item-popup').attr('data-item-id', '')
        $('#share-item-popup').attr('data-item-id', item.item.id)
        $('#share-item-popup').modal({
          keyboard: true,
          show: true,
        })

        $('#share-item-popup').on('shown.bs.modal', e => {
          const tagItInput = $('.tagit-new').find("input[type='text']")
          tagItInput.val('')

          initTagit()
          KRYPTOS.API.getManageShare(item.item.id, shared => {
            // Format share usernames
            for (const share in shared) {
              for (const user in shared[share].users) {
                shared[share].users[user].display_name = KU.formatLine(
                  shared[share].users[user].display_name,
                  25,
                )
              }
            }

            const html = templateManageShareItems({ shared })
            $('#manage-share-items').html(html)
            $('#share-owner').html(
              `Share owner: ${KU.getDisplayNameByUsername(item.item.owner)}`,
            )
            $('select.update-share-item').on('change', function() {
              const select = $(this)
              select.prop('disabled', 'disabled')
              const popup = $('#share-item-popup')
              const itemId = popup.attr('data-item-id')
              if (itemId) {
                const ctxt = $(this)
                  .parent()
                  .parent()
                const user = ctxt.data('user-row')
                const role = ctxt.find('select.share-role').val()
                updateShareItem(itemId, user, role, () => {
                  showSuccessMessage(
                    'Update Successful',
                    "The user's permissions were updated successfully.",
                  )
                  select.prop('disabled', false)
                })
              }
            })
            // WAS HERE DELETE USER
          })
          $('input.ui-autocomplete-input').focus()
        })
      } else {
        $('#share-item-popup-notowner').attr('data-item-id', '')
        $('#share-item-popup-notowner').attr('data-item-id', item.item.id)
        $('#share-item-popup-notowner').modal({
          keyboard: true,
          show: true,
        })
        $('#share-item-popup-notowner').on('shown.bs.modal', e => {
          KRYPTOS.API.getManageShare(item.item.id, shared => {
            const html = templateManageShareItemsNotOwner({ shared })
            $('#manage-share-items-notowner').html(html)
            $('#share-owner-no').html(
              `Share owner: ${KU.getDisplayNameByUsername(item.item.owner)}`,
            )

            // WAS here 2
          })
        })
      }

      popup.attr('data-selected-item-id', '')
      popup.attr('data-item-id', '')
    })
  }

  var initCopyItem = function() {
    $('.copy-item').on('click', function() {
      $('#copy-item-popup').attr('data-item-id', '')
      $('#copy-item-popup').attr('data-item-id', getItemId(this))
      $('#copy-item-popup').modal({
        keyboard: true,
        show: true,
      })
      showFolderTree('copy')
    })
    $('button#confirm-copy-item').on('click', () => {
      const popup = $('#copy-item-popup')
      const newParentId = popup.attr('data-selected-item-id')
      const itemId = popup.attr('data-item-id')
      if (itemId) {
        copyItems(itemId, newParentId)
      }
      $('#copy-item-popup').modal('hide')
      popup.attr('data-selected-item-id', '')
      popup.attr('data-item-id', '')
    })
  }

  var initDeleteItem = function() {
    $('.delete-item').on('click', function() {
      $('#confirm-item-deletion').attr('data-item-id', '')
      $('#confirm-item-deletion').attr('data-item-id', getItemId(this))
      $('#confirm-item-deletion').modal({
        keyboard: true,
        show: true,
      })
    })
    $('button#confirm-delete-item').on('click', () => {
      const itemId = $('#confirm-item-deletion').attr('data-item-id')
      if (itemId) {
        deleteItem(itemId)
      } else {
        $('#confirm-item-deletion').modal('hide')
      }
    })
  }

  var initDeleteUser = function() {
    const popup = $('#confirm-delete-user-popup')
    $('#manage-share-items').on(
      'click',
      'button.remove-share-item-button',
      function() {
        //            var ctxt = $(this).parent().parent();
        const user = $(this).attr('data-user')
        const itemId = $(this).attr('data-item-id')
        popup.attr('data-item-id', '')
        popup.attr('data-item-id', itemId)
        popup.attr('data-user', '')
        popup.attr('data-user', user)
        popup.modal({
          keyboard: true,
          show: true,
        })
      },
    )
    popup.on('click', 'button#confirm-delete-user', () => {
      const itemId = popup.attr('data-item-id')
      const user = popup.attr('data-user')
      popup.attr('data-item-id', '')
      popup.attr('data-user', '')
      if (itemId && user) {
        unshareItem(itemId, user, () => {
          $(`#manage-share-items div.row[data-user-row="${user}"]`).remove() // remove user from list
          popup.modal('hide')
        })
      }
      popup.modal('hide')
    })
  }

  var initLeaveFolder = function() {
    const popup = $('#confirm-leave-folder-popup')
    $('#manage-share-items-notowner').on(
      'click',
      'button.remove-share-item-button-notowner',
      function() {
        const user = $(this).attr('data-user')
        const itemId = $(this).attr('data-item-id')
        popup.attr('data-item-id', '')
        popup.attr('data-item-id', itemId)
        popup.attr('data-user', '')
        popup.attr('data-user', user)
        popup.modal({
          keyboard: true,
          show: true,
        })
      },
    )
    popup.on('click', 'button#confirm-leave-folder', () => {
      const itemId = popup.attr('data-item-id')
      const user = popup.attr('data-user')
      popup.attr('data-item-id', '')
      popup.attr('data-user', '')
      if (itemId && user) {
        unshareItem(itemId, user, () => {
          $(
            `#manage-share-items-notowner div.row[data-user-row="${user}"]`,
          ).remove() // remove user from list
          popup.modal('hide')
          $('#share-item-popup-notowner').modal('hide')
        })
      }
      popup.modal('hide')
    })
  }

  // API
  var deleteItem = function(itemId) {
    CommonDashboard.overlayShow()
    $('#confirm-item-deletion').modal('hide')
    const sendData = {
      item_id: itemId,
      confirm: true,
    }
    KRYPTOS.API.deleteItem(sendData, result => {
      removeChild(itemId)
    })
  }

  // API
  const moveItem = function(itemId, parentId, referenceId, metaData, callback) {
    CommonDashboard.overlayShow()
    const sendData = {
      item_id: itemId,
      parent_id: parentId,
      reference_id: referenceId,
      meta_data: JSON.stringify(metaData),
      confirm: true,
    }
    KRYPTOS.API.moveItem(sendData, callback)
  }

  var initCreateFolder = function() {
    storageContent.on('click', '.create-folder', () => {
      $('#files-container #create-folder-popup').on('shown.bs.modal', e => {
        $('#folder-name').focus()
      })

      $('#files-container #create-folder-popup').on('hide.bs.modal', e => {
        $('#folder-name').val('')
      })

      $('#files-container #create-folder-popup').modal({
        keyboard: true,
        show: true,
      })
    })

    $('.storage-list-view').on('click', function() {
      $('.storage .storage-item')
        .removeClass('folder-view')
        .removeClass('selected')
        .addClass('list-view')
      $('.context-menu li.dropdown').removeClass('open')
      $('a.btn.storage-list-view, a.btn.storage-folder-view').removeClass(
        'active',
      )
      $(this).addClass('active')
      $('.context-menu').addClass('listing')
    })

    $('.storage-folder-view').on('click', function() {
      $('.storage .storage-item')
        .removeClass('list-view')
        .removeClass('selected')
        .addClass('folder-view')
      $('.context-menu li.dropdown').removeClass('open')
      $('a.btn.storage-list-view, a.btn.storage-folder-view').removeClass(
        'active',
      )
      $(this).addClass('active')
      $('.context-menu').removeClass('listing')
    })

    $('button#create-folder-button').on('click', () => {
      const folderName = $('input#folder-name').val()
      if (validateItemName(folderName)) {
        createNewFolder(folderName)
      }
    })

    $('input#folder-name').on('keyup', e => {
      if (e.keyCode === 13) {
        // Enter
        const folderName = $('input#folder-name').val()
        if (validateItemName(folderName)) {
          createNewFolder(folderName)
        }
      }
    })
  }

  var validateItemName = function(itemName) {
    if (!KU.validName(itemName)) {
      showErrorMessage(
        'Invalid Name',
        "Characters \\, /, ?, %, *, :, |, ', &quot;, &lt;, &gt;, &amp; and ; are not allowed.",
      )
      return false
    }
    if (existsIn(currentFolderId(), itemName, true)) {
      return false
    }
    return true
  }

  var existsIn = function(targetItemId, itemName, showError) {
    for (let i = 0; i < items[targetItemId].childs.length; i++) {
      if (items[items[targetItemId].childs[i].id]) {
        const otherItemName = KU.cleanString(
          decodeURIComponent(
            items[items[targetItemId].childs[i].id].item.plain.n,
          ),
        )
        if (
          items[items[targetItemId].childs[i].id] &&
          itemName.toLowerCase() === otherItemName.toLowerCase()
        ) {
          if (showError) {
            if (currentFolder.childs[i].type === 'directory') {
              showErrorMessage(
                'Invalid Name',
                'A folder with that name already exists.',
              )
            } else {
              showErrorMessage(
                'Invalid Name',
                'A file with that name already exists.',
              )
            }
          }
          return true
        }
      }
    }
    return false
  }

  var openFolder = function(itemId) {
    if (itemId && items[itemId]) {
      breadcrumbs.push(itemId)
      items[currentFolderId()] = currentFolder
      currentFolder = items[itemId]
      showBreadcrumbs(itemId)
      storageArea.html('')
      if (itemId === rootFolder.item.id) {
        reset()
      } else {
        getItem(itemId, true)
      }
    }
  }

  var encryptNewFolder = function(name, parentId) {
    return new Promise((resolve, reject) => {
      const folderMetaData = newDirectory(name)
      const plainMetaData = folderMetaData.d
      encryptNewItem(folderMetaData, (metaData, key) => {
        const referenceId = newReferenceId()
        const sendData = {
          parent_id: parentId || currentFolderId(),
          reference_id: referenceId,
          type: 'directory',
          meta_data: metaData,
          part_count: 0,
        }

        resolve({ send_data: sendData, plain_data: plainMetaData, key })
        //                    KRYPTOS.API.addItem(sendData, function(result) {
        //                        if (storageArea.is(':empty')) {
        //                            $('#stormessage').remove();
        //                        }
        //                        items[result.item.id] = result;
        //                        items[result.item.id].item.plain = plainMetaData;
        //                        items[result.item.id].item.plain_key = key;
        //                        items[result.item.id].item.reference_id = referenceId;
        //                        items[result.item.id].childs = [];
        //                        insertItem({id: result.item.id, plain: plainMetaData, type: 'directory'});
        //                        addChild(result.item.id, key, 'directory');
        //                    });
      })
    })
  }

  // API
  var createNewFolder = function(name) {
    CommonDashboard.overlayShow()
    $('input#folder-name').val('')
    $('#create-folder-popup').modal('hide')
    const folderMetaData = newDirectory(name)
    const plainMetaData = folderMetaData.d
    encryptNewItem(folderMetaData, (metaData, key) => {
      const referenceId = newReferenceId()
      const sendData = {
        parent_id: currentFolderId(),
        reference_id: referenceId,
        type: 'directory',
        meta_data: metaData,
        part_count: 0,
      }
      KRYPTOS.API.addItem(sendData, result => {
        if (storageArea.is(':empty')) {
          $('#stormessage').remove()
        }
        items[result.item.id] = result
        items[result.item.id].item.plain = plainMetaData
        items[result.item.id].item.plain_key = key
        items[result.item.id].item.reference_id = referenceId
        items[result.item.id].childs = []
        insertItem({
          id: result.item.id,
          plain: plainMetaData,
          type: 'directory',
        })
        addChild(result.item.id, key, 'directory')
      })
    })
  }

  var currentFolderId = function() {
    return currentFolder.item.id
  }

  var CF = function() {
    return items[currentFolderId()]
  }

  var moveItems = function(itemId, targetItemId) {
    if (targetItemId === currentFolderId()) {
      return
    }
    CommonDashboard.overlayShow()
    $('#move-item-popup').modal('hide')
    const item = items[itemId].item

    const metaData = JSON.parse(item.meta_data)
    let newMetaData = null
    const referenceId = newReferenceId()
    const oldReferenceId = items[itemId].item.reference_id
    item.plain.m = new Date().getTime()
    encryptExistingItem(item.plain, item.plain_key, metaData.iv, result => {
      newMetaData = {
        s: result.signature,
        so: owner,
        iv: result.iv,
        v: metaData.v,
        d: result.message,
      }

      moveItem(item.id, targetItemId, referenceId, newMetaData, () => {
        newMetaData.v += 1 // keep version in sync (increased on server)
        items[itemId].item.meta_data = JSON.stringify(newMetaData)
        items[itemId].item.plain = item.plain
        items[itemId].item.parent_id = targetItemId
        if (items[itemId].item.is_owner || !items[itemId].item.is_shared) {
          items[itemId].item.reference_id = referenceId
        }
        updateTargetFolder(itemId, targetItemId, () => {
          removeChild(item.id, oldReferenceId)
        })
      })
    })
  }

  var shareItem = function(itemId, emails, role, callback) {
    CommonDashboard.overlayShow()
    const recipients = emails.toLowerCase().split(',')
    keyStore.getRecipientsPublicKeys(recipients, (success, message) => {
      if (!success) {
        showErrorMessage('Share Error!', message.errors.username)
      } else {
        const item = items[itemId]
        encryptItemAssignment(item.item.plain_key, recipients, result => {
          const sendData = {
            item_id: itemId,
            users: result,
            role,
          }
          KRYPTOS.API.shareItem(sendData, () => {
            items[itemId].item.is_shared = true
            items[itemId].item.is_owner = true
            items[itemId].item.owner = owner
            // items[itemId].item.cache_share_count = items[itemId].item.cache_share_count;
            refreshItem(items[itemId])
            CommonDashboard.overlayHide()
            callback()
          })
        })
      }
    })
  }

  var updateShareItem = function(itemId, user, role, callback) {
    const sendData = {
      item_id: itemId,
      email: user,
      role,
    }
    KRYPTOS.API.updateShareItem(sendData, () => {
      callback()
    })
  }

  var unshareItem = function(itemId, user, callback) {
    const sendData = {
      item_id: itemId,
      email: user,
    }
    KRYPTOS.API.unshareItem(sendData, () => {
      callback()
    })
  }

  var copyItems = function(itemId, targetItemId) {
    CommonDashboard.overlayShow()
    $('#move-item-popup').modal('hide')
    const item = items[itemId].item
    const plainMetaData = JSON.parse(item.meta_data)
    plainMetaData.d = item.plain

    encryptNewItem(plainMetaData, (metaData, key) => {
      const referenceId = newReferenceId()
      const sendData = {
        item_id: itemId,
        parent_id: targetItemId,
        reference_id: referenceId,
        meta_data: metaData,
      }
      KRYPTOS.API.copyItem(sendData, parent => {
        // Get parent folder to get new copied item id
        if (parent) {
          const temp = [parent.childs.length]
          for (let i = 0; i < parent.childs.length; i++) {
            // look up new child in plain childs
            temp[i] = parent.childs[i]
            for (
              let j = 0;
              j > items[parent.item.id].item.plain.ch.length;
              j++
            ) {
              if (
                parent.childs[i].reference_id ===
                items[parent.item.id].item.plain.ch[j].r
              ) {
                temp.splice(i, 1)
                break
              }
            }
          }
          const targetItem = items[targetItemId]
          const newItem = temp[0]
          items[newItem.id] = {
            childs: [],
            item: newItem,
            item_key: null,
            parent: null,
          }
          items[newItem.id].item.plain = item.plain
          items[newItem.id].item.plain_key = key
          items[newItem.id].item.parent_id = targetItemId
          targetItem.item.plain.ch.push({
            r: referenceId,
            k: key,
            t: items[newItem.id].item.type,
          })
          targetItem.item.plain.m = new Date().getTime()
          updateItem(targetItem)
        }
        CommonDashboard.overlayHide()
      })
    })
  }

  /**
   * Add child items to the current folder.
   *
   * @param {Array} childs
   * @param {function} callback
   * @returns {void}
   */
  var addChilds = function(childs, callback) {
    for (let i = 0; i < childs.length; i++) {
      currentFolder.item.plain.ch.push({
        r: childs[i].rid,
        k: childs[i].key,
        t: childs[i].type,
      })
      currentFolder.childs.push(items[childs[i].id].item)
    }
    currentFolder.item.plain.m = new Date().getTime()
    updateCurrentFolder(callback)
  }

  /**
   * Add a child item to the current folder.
   *
   * @param {string} id
   * @param {string} key
   * @param {string} type
   * @returns {void}
   */
  var addChild = function(id, key, type) {
    currentFolder.item.plain.ch.push({
      r: items[id].item.reference_id,
      k: key,
      t: type,
    })
    currentFolder.item.plain.m = new Date().getTime()
    currentFolder.childs.push(items[id].item)
    updateCurrentFolder()
  }

  var removeChild = function(itemId, referenceId) {
    const refId = referenceId || items[itemId].item.reference_id
    let temp = []
    for (var i = 0; i < currentFolder.item.plain.ch.length; i++) {
      if (currentFolder.item.plain.ch[i].r !== refId) {
        temp.push(currentFolder.item.plain.ch[i])
      }
    }
    currentFolder.item.plain.ch = temp
    temp = []
    for (var i = 0; i < currentFolder.childs.length; i++) {
      if (currentFolder.childs[i].id !== itemId) {
        temp.push(currentFolder.childs[i])
      }
    }
    currentFolder.childs = temp
    $(`.storage-item[data-item-id='${itemId}']`).remove()
    currentFolder.item.plain.m = new Date().getTime()
    updateCurrentFolder()
  }

  var renameItem = function(itemId, name) {
    CommonDashboard.overlayShow()
    const item = items[itemId]
    item.item.plain.n = encodeURIComponent(name)
    item.item.plain.m = new Date().getTime()
    updateItem(item, () => {
      refreshItem(item)
      showFolderTree('menu', item.item.parent_id)
    })
  }

  var updateTargetFolder = function(itemId, targetItemId, callback) {
    const item = items[itemId].item
    const targetFolder = items[targetItemId]
    targetFolder.item.plain.ch.push({
      r: item.reference_id,
      k: item.plain_key,
      t: item.type,
    }) // TODO
    targetFolder.childs.push(item)
    updateItem(targetFolder, callback)
  }

  // API
  var updateCurrentFolder = function(callback) {
    updateItem(currentFolder, callback)
  }

  var updateItem = function(item, callback) {
    const metaData = JSON.parse(item.item.meta_data)
    encryptExistingItem(
      item.item.plain,
      item.item.plain_key,
      metaData.iv,
      result => {
        const newMetaData = {
          s: result.signature,
          so: owner,
          iv: result.iv,
          v: metaData.v,
          d: result.message,
        }
        const sendData = {
          item_id: item.item.id,
          meta_data: JSON.stringify(newMetaData),
          part_count: item.item.plain.p ? item.item.plain.p.length : 0,
        }
        KRYPTOS.API.updateItem(sendData, result => {
          if (result.item) {
            synchUpdateItem(item, result, callback)
            // showErrorMessage("Update Error", "The current folder couldn't be updated. Someone else was updating it. Trying to synchroize...");
          } else {
            if (!hasInit) {
              // Setup mode (default folders)
              if (callback) {
                callback()
              }
              return
            }
            showFolderTree('menu')
            item.item.meta_data = result
            items[item.item.id] = item
            if (storageArea.is(':empty')) {
              storageArea.html(emptyFolderMessage({}))
            } else {
              $('#stormessage').remove()
            }
            if (item.item.id === currentFolder.item.id) {
              currentFolder = item
            }
            CommonDashboard.overlayHide()
            if (callback) {
              callback()
            }
          }
        })
      },
    )
  }

  var synchUpdateItem = function(oldItem, newItem, callback) {
    const itemId = newItem.item.id
    decryptItem(
      newItem.item.meta_data,
      itemId,
      items[itemId].item.reference_id,
      items[itemId].item.plain_key,
      result => {
        // items[result.id] = newItem;
        items[result.id].childs = newItem.childs
        // items[result.id].item.plain = result.plain;
        //            items[result.id].item.plain.n = items[result.id].item.plain.n;
        items[result.id].item.meta_data = newItem.item.meta_data

        //            if (result.t === 'directory') {
        for (let i = 0; i < result.plain.ch.length; i++) {
          if (!childExists(result.plain.ch[i].r, items[itemId].item.plain.ch)) {
            items[itemId].item.plain.ch.push({
              r: result.plain.ch[i].r,
              k: result.plain.ch[i].k,
              t: result.plain.ch[i].t,
            })
          }
          //                    else {
          //                    }
        }
        //            }
        //            if (itemId === currentFolder.item.id) {
        //                currentFolder = items[result.id];
        //            }
        updateItem(items[itemId], () => {
          // getChildren();
          if (callback) {
            callback()
          }
        })
      },
    )
  }

  var childExists = function(rid, childs) {
    for (let j = 0; j < childs.length; j++) {
      if (rid === childs[j].r) {
        return true
      }
    }
    return false
  }

  var initFileUpload = function() {
    $('#upload-files').on('change', function() {
      const files = this.files
      handleFiles(files)
    })
  }

  var initFolderUpload = function() {
    $('#upload-folder').on('change', function() {
      const files = this.files

      for (let i = 0; i < files.length; i++) {}
    })
  }

  const showContextMenu = function(
    type,
    top,
    left,
    itemId,
    itemName,
    itemOwner,
  ) {
    $(`.storage-item[data-item-id="${itemId}"]`).addClass('selected')
    if (type === 'file' && isUploading(itemId)) {
      return
    }
    const contextMenu = $(`#${type}-properties`)

    contextMenu.attr('data-item-id', itemId)
    contextMenu.attr('data-item-owner', itemOwner)
    contextMenu.attr('data-item-name', itemName)
    if ($('.context-menu').hasClass('listing')) {
      contextMenu.css({ position: 'absolute', top, left })
    } else {
      contextMenu.css({ position: 'absolute', top, left })
    }
    contextMenu.children('li.dropdown').addClass('open')
  }

  const resetContextMenu = function() {
    let contextMenu = $('#directory-properties')
    contextMenu.attr('data-item-id', '')
    contextMenu.attr('data-item-owner', '')
    contextMenu.attr('data-item-name', '')

    contextMenu = $('#file-properties')
    contextMenu.attr('data-item-id', '')
    contextMenu.attr('data-item-owner', '')
    contextMenu.attr('data-item-name', '')

    contextMenu = $('#upload-properties')
    contextMenu.attr('data-item-id', '')
    contextMenu.attr('data-item-owner', '')
    contextMenu.attr('data-item-name', '')
  }

  var initProperties = function() {
    $('.storage').on('contextmenu', e => {
      e.stopPropagation()
      e.preventDefault()
      const storageOffset = $('.storage').offset()
      $('.context-menu li.dropdown').removeClass('open')
      $('.storage-item').removeClass('selected')
      const element = $(e.target)
      let top = 0,
        left = 0
      let type = ''
      let itemId = null
      if (element.hasClass('directory') || element.hasClass('file')) {
        type = element.hasClass('directory') ? 'directory' : 'file'
        const parent = element.parent()
        parent.addClass('selected')
        itemId = parent.attr('data-item-id')
        const parentOffset = parent.offset()
        top = parentOffset.top - storageOffset.top + e.offsetY
        left = parentOffset.left - storageOffset.left + e.offsetX
      } else if (element.hasClass('storage-item')) {
        type = element.hasClass('directory') ? 'directory' : 'file'
        element.addClass('selected')
        itemId = element.attr('data-item-id')
        var thisOffset = element.offset()
        top = thisOffset.top - e.offsetY
        left = thisOffset.left - storageOffset.left + e.offsetX
      } else if (
        element.hasClass('storage-area') ||
        element.hasClass('ghostdrop')
      ) {
        type = 'upload'
        var thisOffset = element.offset()
        top = thisOffset.top - storageOffset.top + e.offsetY
        left = e.offsetX
      } else {
        return
      }
      if (itemId || type === 'upload') {
        showContextMenu(type, top, left, itemId)
      }
    })

    $('.storage').on('click', '.storage-item .item-options', function(e) {
      e.preventDefault()
      $('.context-menu li.dropdown').removeClass('open')
      const storageOffset = $('.storage').offset()
      const parent = $(this).parent('.storage-item')
      const parentOffset = parent.offset()
      const top = parentOffset.top - storageOffset.top + e.offsetY
      let left = parentOffset.left - storageOffset.left + e.offsetX
      const type = parent.attr('data-item-type')
      const itemId = parent.attr('data-item-id')
      const itemName = parent.attr('title')
      const itemOwner = parent.attr('data-owner')
      parent.addClass('selected')
      if ($('.context-menu').hasClass('listing')) {
        left = '85%'
      }
      showContextMenu(type, top, left, itemId, itemName, itemOwner)
    })

    $('.storage').on('dblclick', 'div.directory', function(e) {
      e.preventDefault()
      const itemId = $(this).attr('data-item-id')
      openFolder(itemId)
    })
    $('.storage').on('dblclick', 'div.file', function(e) {
      e.preventDefault()
      const itemId = $(this).attr('data-item-id')
      if (isUploading(itemId)) {
        return
      }
      downloadFile(itemId)
    })
    $('.storage').on('click', '.storage-item', function(e) {
      e.preventDefault()
      const target = $(e.target)
      $('.storage-item').removeClass('selected')
      if (!target.hasClass('item-options')) {
        $('.context-menu li.dropdown').removeClass('open')
      }
      $(this).addClass('selected')
    })
    $('.storage').on('click', e => {
      e.preventDefault()

      const target = $(e.target)
      if (
        !target.hasClass('directory') &&
        !target.hasClass('file') &&
        !target.hasClass('storage-item') &&
        !target.hasClass('item-options')
      ) {
        $('.context-menu li.dropdown').removeClass('open')
        resetContextMenu()
        if (
          !target.hasClass('share-item') &&
          !target.hasClass('copy-item') &&
          !target.hasClass('move-item') &&
          !target.hasClass('rename-item') &&
          !target.hasClass('item-ino')
        ) {
          $('.storage-item').removeClass('selected')
        }
      }
    })
  }

  var getItemId = function(obj) {
    const parent = $(obj).closest('.context-menu')
    return parent.attr('data-item-id')
  }

  var initActions = function() {
    storageContent.on('click', '.upload-files', e => {
      e.preventDefault()
      uploadFiles()
    })
    //        storageContent.on('click', '.create-folder', function(e) {
    //            e.preventDefault();
    //            newFolder(false);
    //        });
    $('.open-folder').click(function(e) {
      e.preventDefault()
      openFolder(getItemId(this))
    })
    $('.item-info').click(function(e) {
      e.preventDefault()
      const item = items[getItemId(this)]
      showItemInfo(item.item)
    })
    $('.download-item').click(function(e) {
      e.preventDefault()
      downloadFile(getItemId(this))
    })
    $('#breadcrumbs').on('click', 'li a', function(e) {
      e.preventDefault()
      const itemId = $(this).attr('data-item-id')
      handleBreadcrumb(itemId)
    })
    $('#file-transfer .file-transfer-header').click(e => {
      e.preventDefault()
      toggleFileTransfer()
    })
    $('#file-transfer-toggle').click(e => {
      e.preventDefault()
      showFileTransfer()
    })
  }

  var updateFileTransferCount = function() {
    const count = $('#file-transfer tbody.files tr').length
    $('.file-transfer-count').html(count)
    if (count === 0) {
      toggleFileTransfer()
    }
  }

  var toggleFileTransfer = function() {
    if ($('#file-transfer').is(':visible')) {
      $('#file-transfer').animate(
        {
          bottom: '-270px',
        },
        1000,
        () => {
          $('#file-transfer-toggle').show()
        },
      )
    } else {
      showFileTransfer()
    }
  }

  var showFileTransfer = function() {
    if ($('#file-transfer').not(':visible')) {
      $('#file-transfer')
        .show()
        .animate(
          {
            bottom: '0px',
          },
          1200,
        )
      $('#file-transfer-toggle').hide()
    }
  }

  var showItemInfo = function(item) {
    if (item) {
      const parsed = JSON.parse(item.meta_data)
      const obj = {
        name: KU.cleanString(decodeURIComponent(item.plain.n)),
        type: item.type,
        icon:
          item.type === 'directory'
            ? 'fa-folder'
            : mimeTypeToIcon(item.plain.mt),
        size: KU.bytesToSize(
          item.type === 'directory'
            ? item.cache_item_size_recursive
            : item.plain.s,
        ),
        created: item.plain.c === null ? '' : KU.localDateTime(item.plain.c),
        modified: item.plain.m === null ? '' : KU.localDateTime(item.plain.m),
        user: KU.getDisplayNameByUsername(parsed.so),
      }
      const html = templateStorageItemInfo(obj)
      $('#item-info div.modal-body').html(html)
      $('#item-info').modal({
        keyboard: true,
        show: true,
      })
    }
  }

  var handleBreadcrumb = function(itemId) {
    if (itemId && items[itemId]) {
      if (itemId === rootFolder.item.id) {
        reset()
        return
      }
      if (itemId === currentFolderId()) {
        getItem(itemId, true)
        return
      }
      const temp = []
      for (let i = 0; i < breadcrumbs.length; i++) {
        temp[i] = breadcrumbs[i]
        if (breadcrumbs[i] === itemId) {
          break
        }
      }
      breadcrumbs = []
      breadcrumbs = temp

      currentFolder = items[itemId]
      getItem(itemId, true)

      showBreadcrumbs(itemId)
    } else {
    }
    // getChildren();
  }

  const showSplash = function() {
    storageContent.find('#storage-content').hide()
    reset(true)
    storageIntro.show()
  }

  var showFiles = function(dontRefresh, openFolderId, justShow) {
    storageIntro.hide()
    storageContent.find('#storage-content').show()
    if (justShow) {
      return
    }
    if (!dontRefresh) {
      reset(false, openFolderId)
    } else {
      getChildren(true)
    }
  }

  const isRootFolder = function() {
    const cid = currentFolderId()
    return !cid || !rootFolder.item.id || cid === rootFolder.item.id
  }

  const newFolder = function() {
    if (isRootFolder()) {
      showFiles(true)
    }
    storageContent
      .find('.create-folder')
      .first()
      .click()
  }

  var uploadFiles = function() {
    if (isRootFolder()) {
      showFiles()
    }
    const fileInput = $('<input type="file" multiple />')
    fileInput.on('change', function() {
      const files = this.files
      handleFiles(files)
    })
    fileInput.click()
  }

  const shareFolder = function() {
    if (!isRootFolder()) {
      storageContent
        .find('.share-item')
        .first()
        .click()
    } else {
      $('#share-tree-item-popup').attr('data-selected-item-id', '')
      $('#share-tree-item-popup').modal({
        keyboard: true,
        show: true,
      })
      showFolderTree('share-tree')
    }
  }

  const isInitialized = function() {
    return hasInit
  }

  return {
    init,
    setup,
    getShares,
    showSplash,
    showFiles,
    newFolder,
    uploadFiles,
    shareFolder,
    acceptShare,
    isInitialized,
  }
})()

/**
 * 1. Fix current folder
 * 2. Fix upload in shared folder - file parts synch or update parent after upload finish
 * 3. Fix update synch
 */
