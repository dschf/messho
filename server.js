const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const multer = require('multer');
const crypto = require('crypto');
const mongoose = require('mongoose');
const cloudinary = require('cloudinary').v2;
const dns = require('dns');

// Fix DNS resolution for MongoDB Atlas on some networks
dns.setDefaultResultOrder('ipv4first');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Atlas Connection
const MONGO_URI = 'mongodb+srv://anandkumarjj22_db_user:Ad6769V1ltazOu0A@messho.xd93yju.mongodb.net/meesho?retryWrites=true&w=majority';

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Atlas connected successfully!'))
    .catch(err => console.error('MongoDB connection error:', err));

// Cloudinary Configuration (cloud_name is lowercase L, not digit 1)
cloudinary.config({
    cloud_name: 'x5lpaifh',
    api_key: '928732116388271',
    api_secret: 'sP34Z7ogukEv09s9L8Sj-cETZLk'
});

// Mongoose Schemas
const ProductSchema = new mongoose.Schema({
    id: Number,
    name: String,
    category: String,
    price: Number,
    original_price: Number,
    discount: Number,
    image: String,
    images: [String],
    description: String,
    sizes: [String],
    rating: Number,
    ratingCount: Number,
    reviewCount: Number,
    reviews: Array,
    specs: Array,
    supplierName: String,
    supplierRating: Number,
    supplierRatingCount: Number
});
const Product = mongoose.model('Product', ProductSchema);

const ConfigSchema = new mongoose.Schema({
    upiId: String,
    scrapeopsApiKey: String,
    googleScriptUrl: String
});
const Config = mongoose.model('Config', ConfigSchema);

// Enable CORS and body parsing
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure temp upload directory exists
const tempUploadsDir = path.join(__dirname, 'temp_uploads');
if (!fs.existsSync(tempUploadsDir)) {
    fs.mkdirSync(tempUploadsDir, { recursive: true });
}

// Ensure images directory exists (for backward compatibility serving old local images)
const imagesDir = path.join(__dirname, 'images');
if (!fs.existsSync(imagesDir)) {
    fs.mkdirSync(imagesDir, { recursive: true });
}

// Multer storage configuration — temp directory, files deleted after Cloudinary upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, tempUploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname) || '.png';
        cb(null, 'upload-' + uniqueSuffix + ext);
    }
});
const upload = multer({ storage: storage });

// Helper: Upload a local file to Cloudinary and return the secure URL
async function uploadToCloudinary(filePath) {
    const result = await cloudinary.uploader.upload(filePath, { folder: 'meesho_products' });
    return result.secure_url;
}

// Helper: Download a remote image to temp, upload to Cloudinary, clean up temp
async function downloadAndUploadToCloudinary(remoteUrl) {
    const cleanUrl = remoteUrl.split('?')[0];
    const ext = path.extname(cleanUrl) || '.webp';
    const tempFile = path.join(tempUploadsDir, `dl-${Date.now()}-${Math.round(Math.random() * 1E9)}${ext}`);

    await downloadExternalImage(remoteUrl, tempFile);
    try {
        const cloudUrl = await uploadToCloudinary(tempFile);
        return cloudUrl;
    } finally {
        // Always clean up temp file
        if (fs.existsSync(tempFile)) fs.unlinkSync(tempFile);
    }
}

// Active secure admin session keys registry
const activeSessions = new Set();

// Track failed login attempts by IP to prevent brute force
const loginAttempts = {};

// Custom Cookie parser helper
function getCookie(req, name) {
    const cookies = req.headers.cookie || '';
    const parts = cookies.split(';');
    for (let p of parts) {
        const [k, v] = p.split('=').map(x => x.trim());
        if (k === name) return v;
    }
    return null;
}

// Security Interceptor Middleware
app.use((req, res, next) => {
    if (req.path.endsWith('admin.html')) {
        return res.redirect('/admin/login');
    }
    next();
});

// Serve static assets from meesho folder (placed AFTER secure interceptors)
app.use(express.static(__dirname));

// Serve Admin Dashboard page (Authorized only)
app.get('/admin', (req, res) => {
    const token = getCookie(req, 'admin_session');
    if (token && activeSessions.has(token)) {
        res.sendFile(path.join(__dirname, 'admin.html'));
    } else {
        res.redirect('/admin/login');
    }
});

// Serve Admin Login Page
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// API Endpoint: Authenticate Admin Credentials with Rate Limiting (5 Attempts max)
app.post('/api/admin/login', (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip || req.socket.remoteAddress || 'unknown';

    const currentAttempts = loginAttempts[ip] || 0;
    if (currentAttempts >= 5) {
        return res.status(429).json({ success: false, error: 'Too many login attempts. Access blocked for 60 seconds.' });
    }

    if (username === 'admin' && password === 'AdminPassword@123') {
        delete loginAttempts[ip];
        const token = crypto.randomBytes(32).toString('hex');
        activeSessions.add(token);
        res.setHeader('Set-Cookie', 'admin_session=' + token + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400');
        res.json({ success: true });
    } else {
        const newAttempts = currentAttempts + 1;
        loginAttempts[ip] = newAttempts;

        if (newAttempts >= 5) {
            setTimeout(() => { delete loginAttempts[ip]; }, 60000);
            res.status(429).json({ success: false, error: 'Too many login attempts. Access blocked for 60 seconds.' });
        } else {
            res.status(401).json({ success: false, error: `Invalid credentials. ${5 - newAttempts} attempts remaining.` });
        }
    }
});

// API Endpoint: Terminate Admin Session
app.post('/api/admin/logout', (req, res) => {
    const token = getCookie(req, 'admin_session');
    if (token) {
        activeSessions.delete(token);
    }
    res.setHeader('Set-Cookie', 'admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
    res.json({ success: true });
});

// Default route to serve index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ====================== DATABASE-BACKED API ROUTES ======================

// API Endpoint: Get configuration (current UPI, active products count, proxy key, google script) — FROM MONGODB
app.get('/api/config', async (req, res) => {
    try {
        const config = await Config.findOne();
        const upiId = config ? config.upiId : 'Not Set';
        const scrapeopsApiKey = config ? config.scrapeopsApiKey : '';
        const googleScriptUrl = config ? config.googleScriptUrl : '';
        const productsCount = await Product.countDocuments();
        res.json({ upiId, scrapeopsApiKey, googleScriptUrl, productsCount });
    } catch (e) {
        console.error('Error reading config from DB:', e);
        res.json({ upiId: 'Not Set', scrapeopsApiKey: '', googleScriptUrl: '', productsCount: 0 });
    }
});

// API Endpoint: Update Configurations (UPI, ScrapeOps Key, Google Script) — TO MONGODB
app.post('/api/update-upi', async (req, res) => {
    const { upiId, scrapeopsApiKey, googleScriptUrl } = req.body;
    if (!upiId) {
        return res.status(400).json({ error: 'UPI ID is required' });
    }

    try {
        await Config.findOneAndUpdate({}, { 
            upiId: upiId.trim(),
            scrapeopsApiKey: scrapeopsApiKey ? scrapeopsApiKey.trim() : '',
            googleScriptUrl: googleScriptUrl ? googleScriptUrl.trim() : ''
        }, { upsert: true });
        res.json({ success: true, message: 'Settings updated successfully' });
    } catch (e) {
        console.error('Error writing config to DB:', e);
        res.status(500).json({ error: 'Failed to save settings' });
    }
});

// Helper function to fetch page HTML (with redirect support)
function fetchPage(targetUrl, depth = 0) {
    return new Promise((resolve, reject) => {
        if (depth > 5) {
            reject(new Error("Too many redirects"));
            return;
        }

        const urlObj = new URL(targetUrl);
        const options = {
            hostname: urlObj.hostname,
            path: urlObj.pathname + urlObj.search,
            headers: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache'
            }
        };

        https.get(options, (res) => {
            if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                // Resolve relative path if needed
                let redirectUrl = res.headers.location;
                if (!redirectUrl.startsWith('http')) {
                    redirectUrl = new URL(redirectUrl, urlObj.origin).href;
                }
                console.log(`Following redirect to: ${redirectUrl}`);
                resolve(fetchPage(redirectUrl, depth + 1));
                return;
            }

            if (res.statusCode !== 200) {
                reject(new Error(`Server returned status code: ${res.statusCode}`));
                return;
            }

            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

// Helper function to download remote images to a local temp file
function downloadExternalImage(url, dest) {
    return new Promise((resolve, reject) => {
        const file = fs.createWriteStream(dest);
        const client = url.startsWith('https') ? https : http;
        const options = {
            headers: {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1'
            }
        };

        client.get(url, options, (response) => {
            if (response.statusCode !== 200) {
                file.close(() => {
                    fs.unlink(dest, () => { });
                    reject(new Error(`Failed to download image: ${response.statusCode}`));
                });
                return;
            }
            response.pipe(file);
            file.on('finish', () => {
                file.close(resolve);
            });
        }).on('error', (err) => {
            file.close(() => {
                fs.unlink(dest, () => { });
                reject(err);
            });
        });
    });
}

// API Endpoint: Scrape Meesho PDP details
app.post('/api/fetch-product-details', async (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required.' });
    }

    console.log(`Scraping details for Meesho URL: ${url}`);
    try {
        let html;
        const config = await Config.findOne();
        
        if (config && config.googleScriptUrl) {
            console.log("Using Google Apps Script Proxy for Cloud scraping...");
            const proxyUrl = `${config.googleScriptUrl}?url=${encodeURIComponent(url)}`;
            html = await fetchPage(proxyUrl);
        } else if (config && config.scrapeopsApiKey) {
            console.log("Using ScrapeOps Proxy for Cloud scraping...");
            const proxyUrl = `https://proxy.scrapeops.io/v1/?api_key=${config.scrapeopsApiKey}&url=${encodeURIComponent(url)}`;
            html = await fetchPage(proxyUrl);
        } else {
            console.log("Using Direct fetch...");
            html = await fetchPage(url);
        }

        const match = html.match(/<script id="__NEXT_DATA__" type="application\/json">([\s\S]*?)<\/script>/);
        if (!match) {
            return res.status(500).json({ error: 'Could not find __NEXT_DATA__ tag in Meesho PDP page. Is URL correct?' });
        }

        const nextData = JSON.parse(match[1]);
        const details = nextData.props?.pageProps?.initialState?.product?.details?.data;

        if (!details) {
            return res.status(500).json({ error: 'Could not find details block inside page payload.' });
        }

        const name = details.review_summary?.data?.review?.product_name || details.name || "Auto Ingested Product";
        const description = details.description || "";
        const images = details.images || [];

        const supplier = details.suppliers?.[0];
        const priceDetails = supplier?.price_details;
        const sellingPrice = supplier?.price || 0;
        const mrp = priceDetails?.mrp_price?.amount || sellingPrice;

        const sizes = [];
        if (supplier?.inventory) {
            supplier.inventory.forEach(inv => {
                if (inv.variation?.name) {
                    sizes.push(inv.variation.name);
                }
            });
        }
        if (sizes.length === 0) sizes.push("Free Size");

        const revSummary = details.review_summary?.data;
        const rating = revSummary?.average_rating || 4.0;
        const ratingCount = revSummary?.rating_count || 120;
        const reviewCount = revSummary?.review_count || 35;

        const supplierName = supplier?.name || "RP STORE -01";
        const supplierRating = supplier?.average_rating || 4.0;
        const supplierRatingCount = supplier?.rating_count || 1200;

        const reviews = [];
        if (revSummary?.reviews && Array.isArray(revSummary.reviews)) {
            revSummary.reviews.slice(0, 10).forEach(r => {
                reviews.push({
                    author: r.author?.name || r.reviewer_name || "Meesho User",
                    rating: r.rating || 5,
                    comment: r.comments || "Very nice product, fully satisfied!"
                });
            });
        }
        if (reviews.length === 0 && revSummary?.review) {
            reviews.push({
                author: revSummary.review.author?.name || revSummary.review.reviewer_name || "Meesho User",
                rating: revSummary.review.rating || 5,
                comment: revSummary.review.comments || "Good product!"
            });
        }

        const specs = description.split('\n').map(l => l.trim()).filter(l => l && l.includes(':'));

        res.json({
            success: true, name, mrp, sellingPrice, description, images, sizes,
            rating, ratingCount, reviewCount, reviews, specs,
            supplierName, supplierRating, supplierRatingCount
        });

    } catch (err) {
        console.error('Error fetching PDP details:', err);
        res.status(500).json({ error: `Server failed to scrape details: ${err.message}` });
    }
});

// API Endpoint: Save scraped Meesho product — TO MONGODB + CLOUDINARY
app.post('/api/save-product-auto', async (req, res) => {
    try {
        const { name, mrp, category, sellingPrice, description, images, sizes, rating, ratingCount, reviewCount, reviews, specs, supplierName, supplierRating, supplierRatingCount } = req.body;

        if (!name || !category || !sellingPrice) {
            return res.status(400).json({ error: 'Name, Category, and Target Selling Price are required.' });
        }

        // Download external images, upload to Cloudinary, get cloud URLs
        const cloudImageUrls = [];
        if (images && images.length > 0) {
            for (let i = 0; i < images.length; i++) {
                try {
                    const cloudUrl = await downloadAndUploadToCloudinary(images[i]);
                    cloudImageUrls.push(cloudUrl);
                } catch (err) {
                    console.error(`Failed to process image ${i}:`, err.message);
                }
            }
        }

        let parsedPrice = parseInt(String(sellingPrice).replace(/[^0-9]/g, ''), 10);
        let parsedOriginalPrice = mrp ? parseInt(String(mrp).replace(/[^0-9]/g, ''), 10) : parsedPrice;

        if (isNaN(parsedPrice)) {
            return res.status(400).json({ error: 'Invalid selling price numeric format.' });
        }

        if (parsedOriginalPrice < parsedPrice) {
            const temp = parsedPrice;
            parsedPrice = parsedOriginalPrice;
            parsedOriginalPrice = temp;
        }

        const pDiff = parsedOriginalPrice - parsedPrice;
        const discount = parsedOriginalPrice > 0 ? Math.round((pDiff / parsedOriginalPrice) * 100) : 0;

        const newProduct = new Product({
            id: Date.now(),
            name: name.trim(),
            category: category.trim(),
            price: parsedPrice,
            original_price: parsedOriginalPrice,
            discount: discount,
            image: cloudImageUrls[0] || 'images/default.png',
            images: cloudImageUrls,
            description: description || '',
            sizes: sizes || ['Free Size'],
            rating: parseFloat(rating) || 4.0,
            ratingCount: parseInt(ratingCount, 10) || 100,
            reviewCount: parseInt(reviewCount, 10) || 30,
            reviews: reviews || [],
            specs: specs || [],
            supplierName: supplierName || 'RP STORE -01',
            supplierRating: parseFloat(supplierRating) || 4.0,
            supplierRatingCount: parseInt(supplierRatingCount, 10) || 1200
        });

        await newProduct.save();
        res.json({ success: true, message: 'Product auto-saved successfully!', product: newProduct });
    } catch (e) {
        console.error('Error saving auto product:', e);
        res.status(500).json({ error: 'Server error during save.' });
    }
});

// API Endpoint: Add new product with manual file uploads — TO MONGODB + CLOUDINARY
app.post('/api/add-product', upload.array('images', 10), async (req, res) => {
    try {
        const { name, category, price, original_price, description, sizes, supplierName, supplierRating, supplierRatingCount } = req.body;

        if (!name || !category || !price) {
            return res.status(400).json({ error: 'Name, Category, and Price are required fields.' });
        }

        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'At least one product image file is required.' });
        }

        // Upload each temp file to Cloudinary, then delete temp
        const cloudImageUrls = [];
        for (const file of req.files) {
            try {
                const cloudUrl = await uploadToCloudinary(file.path);
                cloudImageUrls.push(cloudUrl);
            } catch (err) {
                console.error(`Failed to upload ${file.filename} to Cloudinary:`, err.message);
            } finally {
                // Clean up temp file
                if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
            }
        }

        if (cloudImageUrls.length === 0) {
            return res.status(500).json({ error: 'Failed to upload any images to cloud storage.' });
        }

        let parsedPrice = parseInt(price.replace(/[^0-9]/g, ''), 10);
        let parsedOriginalPrice = original_price ? parseInt(original_price.replace(/[^0-9]/g, ''), 10) : parsedPrice;

        if (isNaN(parsedPrice)) {
            return res.status(400).json({ error: 'Invalid selling price numeric format.' });
        }

        if (parsedOriginalPrice < parsedPrice) {
            const temp = parsedPrice;
            parsedPrice = parsedOriginalPrice;
            parsedOriginalPrice = temp;
        }

        const pDiff = parsedOriginalPrice - parsedPrice;
        const discount = parsedOriginalPrice > 0 ? Math.round((pDiff / parsedOriginalPrice) * 100) : 0;

        let sizesArray = [];
        if (sizes && sizes.trim() !== '' && sizes.trim().toLowerCase() !== 'none') {
            sizesArray = sizes.split(',').map(s => s.trim()).filter(s => s);
        }

        const newProduct = new Product({
            id: Date.now(),
            name: name.trim(),
            category: category.trim(),
            price: parsedPrice,
            original_price: parsedOriginalPrice,
            discount: discount,
            image: cloudImageUrls[0],
            images: cloudImageUrls,
            description: description || '',
            sizes: sizesArray,
            rating: parseFloat(supplierRating) || 4.0,
            ratingCount: parseInt(supplierRatingCount, 10) || 120,
            reviewCount: Math.round((parseInt(supplierRatingCount, 10) || 120) * 0.3),
            reviews: [],
            specs: [],
            supplierName: supplierName || 'RP STORE -01',
            supplierRating: parseFloat(supplierRating) || 4.0,
            supplierRatingCount: parseInt(supplierRatingCount, 10) || 1200
        });

        await newProduct.save();
        res.json({ success: true, message: 'Product added manually successfully!', product: newProduct });
    } catch (e) {
        console.error('Error adding product manually:', e);
        res.status(500).json({ error: 'Server error adding product.' });
    }
});

// API Endpoint: Edit existing product details — IN MONGODB + CLOUDINARY
app.post('/api/edit-product', upload.array('images', 10), async (req, res) => {
    try {
        const { id, name, category, price, original_price, description, sizes, supplierName, supplierRating, supplierRatingCount } = req.body;

        if (!id || !name || !category || !price) {
            return res.status(400).json({ error: 'ID, Name, Category, and Price are required fields.' });
        }

        const product = await Product.findOne({ id: parseInt(id) });
        if (!product) {
            return res.status(404).json({ error: 'Product not found.' });
        }

        let parsedPrice = parseInt(price.replace(/[^0-9]/g, ''), 10);
        let parsedOriginalPrice = original_price ? parseInt(original_price.replace(/[^0-9]/g, ''), 10) : parsedPrice;

        if (isNaN(parsedPrice)) {
            return res.status(400).json({ error: 'Invalid selling price numeric format.' });
        }

        if (parsedOriginalPrice < parsedPrice) {
            const temp = parsedPrice;
            parsedPrice = parsedOriginalPrice;
            parsedOriginalPrice = temp;
        }

        const pDiff = parsedOriginalPrice - parsedPrice;
        const discount = parsedOriginalPrice > 0 ? Math.round((pDiff / parsedOriginalPrice) * 100) : 0;

        let sizesArray = [];
        if (sizes && sizes.trim() !== '' && sizes.trim().toLowerCase() !== 'none') {
            sizesArray = sizes.split(',').map(s => s.trim()).filter(s => s);
        }

        // If new images were uploaded, upload them to Cloudinary
        let updatedImages = product.images;
        let updatedMainImage = product.image;

        if (req.files && req.files.length > 0) {
            const cloudImageUrls = [];
            for (const file of req.files) {
                try {
                    const cloudUrl = await uploadToCloudinary(file.path);
                    cloudImageUrls.push(cloudUrl);
                } catch (err) {
                    console.error(`Failed to upload ${file.filename} to Cloudinary:`, err.message);
                } finally {
                    if (fs.existsSync(file.path)) fs.unlinkSync(file.path);
                }
            }
            if (cloudImageUrls.length > 0) {
                updatedImages = cloudImageUrls;
                updatedMainImage = cloudImageUrls[0];
            }
        }

        product.name = name.trim();
        product.category = category.trim();
        product.price = parsedPrice;
        product.original_price = parsedOriginalPrice;
        product.discount = discount;
        product.image = updatedMainImage;
        product.images = updatedImages;
        product.description = description || '';
        product.sizes = sizesArray;
        product.rating = parseFloat(supplierRating) || 4.0;
        product.ratingCount = parseInt(supplierRatingCount, 10) || 120;
        product.reviewCount = Math.round((parseInt(supplierRatingCount, 10) || 120) * 0.3);
        product.supplierName = supplierName || 'RP STORE -01';
        product.supplierRating = parseFloat(supplierRating) || 4.0;
        product.supplierRatingCount = parseInt(supplierRatingCount, 10) || 1200;

        await product.save();
        res.json({ success: true, message: 'Product updated successfully!', product });
    } catch (e) {
        console.error('Error editing product:', e);
        res.status(500).json({ error: 'Server error editing product.' });
    }
});

// API Endpoint: Delete product by ID — FROM MONGODB
app.post('/api/delete-product', async (req, res) => {
    const { id } = req.body;
    if (!id) {
        return res.status(400).json({ error: 'Product ID is required.' });
    }

    try {
        await Product.deleteOne({ id: parseInt(id) });
        res.json({ success: true, message: 'Product deleted successfully.' });
    } catch (e) {
        console.error('Error deleting product:', e);
        res.status(500).json({ error: 'Server error deleting product.' });
    }
});

// API Endpoint: Get all products — FROM MONGODB
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find({}).lean();
        res.json(products);
    } catch (e) {
        console.error('Error fetching products from DB:', e);
        res.json([]);
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Meesho mobile clone server running on http://localhost:${PORT}`);
});
