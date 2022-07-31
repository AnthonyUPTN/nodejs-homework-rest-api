const multer = require('multer');
const path = require('path'); 

const tmpDir = path.join(__dirname, '../', 'tmp')

const mutlerConfig = multer.diskStorage({
    destination: tmpDir,
    filename: (req, file, cb) => {
        cb(null, file.originalname);
    },
})

const upload = multer({
    storage: mutlerConfig,
})

module.exports = upload;