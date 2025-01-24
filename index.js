const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
require('dotenv').config()
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const app = express();
const cors = require('cors');
const port = process.env.PORT || 4000;

app.use(cors());
app.use(express.json())
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_user}:${process.env.DB_pass}@cluster0.ihuxcck.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
    const client = new MongoClient(uri, {
        serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
        }
    });

    const dbConnect = async () => {
        try {
        client.connect();
        console.log("Database Connected Successfully✅");
    
        } catch (error) {
        console.log(error.name, error.message);
        }
    }

    dbConnect()

    const usersCollection = client.db('MovieManagement').collection('user');
    const moviesCollection = client.db('MovieManagement').collection('movie');
    const ratingsCollection = client.db('MovieManagement').collection('rating');
    const reportsCollection = client.db('MovieManagement').collection('report');
    

    app.get('/',(req,res)=>{
        res.send('Server is runnning')
    })

    // checking authentication middleware
    const authMiddleware = (req, res, next) => {
      const token = req.cookies?.accessToken || req.headers.authorization?.split(' ')[1];
    
      if (!token) {
          return res.status(401).json({ message: 'Authentication token is missing' });
      }
  
      try {
          const decoded = jwt.verify(token, process.env.JWT_SECRET);
          req.user = decoded;
          next();
      } catch (error) {
          console.error('Authentication error:', error);
          return res.status(401).json({ message: 'Invalid or expired token' });
      }
    };

    // user register
    app.post('/control/register', async (req, res) => {
      const { username, email, password } = req.body;
    
      if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
      }
    
      try {
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
    
        const newUser = {
          username,
          email,
          password: hashedPassword,
          role: "user",
          created_at: new Date(),
          updated_at: new Date(),
        };
        await usersCollection.insertOne(newUser);
    
        const { password: _, ...userWithoutPassword } = newUser;
        res.status(201).json({ message: 'User registered successfully', user: userWithoutPassword });
      } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'An error occurred during registration', error: error.message });
      }
    });
    
    // Login Endpoint
    app.post('/control/login', async (req, res) => {
      const { identifier, password } = req.body;

      try {
        let user;
        //Indentify Identifier is a email or username
        if (identifier.includes('@')) {
          user = await usersCollection.findOne({ email: identifier });
        } else {
          user = await usersCollection.findOne({ username: identifier });
        }

        if (!user) {
          return res.status(401).json({ message: 'Invalid email, username, or password' });
        }

        let passwordMatch = false;
        if (user.password.startsWith('$2b$')) {
          passwordMatch = await bcrypt.compare(password, user.password);
        }
        else {
          passwordMatch = user.password === password;
          if (passwordMatch) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await usersCollection.updateOne(
              { _id: user._id },
              { $set: { password: hashedPassword } }
            );
          }
        }

        if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email, username, or password' });
        }
        // Step 3: Generate JWT Token
        const payload = { sub: user._id, email: user.email, username: user.username, role: user.role };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' });
        
        // Step 4: Set cookies
        res.cookie('accessToken', token, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });

        res.cookie('user', JSON.stringify(user), { 
          httpOnly: false, // Accessible to client-side scripts 
          secure: process.env.NODE_ENV === 'production', 
          maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days 
        });

        // Step 5: Send response
        res.status(200).json({ message: 'Login successful' });
      }catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'An error occurred during login', error: error.message });
      }
    })

    //log out account
    app.post('/control/logout', (req, res) => {
      try {
        // Clear the cookies
        res.clearCookie('accessToken', {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
        });
    
        res.clearCookie('user', {
          httpOnly: false,
          secure: process.env.NODE_ENV === 'production',
        });
    
        // Send a response
        res.status(200).json({ message: 'Logout successful' });
      } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).json({ message: 'An error occurred during logout', error: error.message });
      }
    });
  
    //getting all movie list
    app.get('/control/allmovie', authMiddleware, async(req,res) => {
      const result = await moviesCollection.find().toArray();
      res.send(result);
    })

    //only user movie who loged in
    app.get('/control/ownmovie', authMiddleware, async (req, res) => {
      const username = req.user.username;
      
      try {
        // Find all movies added by this user
        const userMovies = await moviesCollection.find({ created_by : username }).toArray();
    
        if (!userMovies.length) {
          return res.status(404).json({ message: 'No movies found for this user' });
        }
    
        res.status(200).json({ message: 'Movies retrieved successfully', movies: userMovies });
      } catch (error) {
        console.error('Error fetching user movies:', error);
        res.status(500).json({ message: 'An error occurred while fetching user movies', error: error.message });
      }
    });

    //movie details
    app.get('/control/movie/:id', authMiddleware, async (req, res) => {
      const movieId = req.params.id;
      try {
        // find the movie with id using findOne
        const movieDetails = await moviesCollection.findOne({ _id: new ObjectId(movieId) });
        
        if (!movieDetails) {
          return res.status(404).json({ message: 'No movie found' });
        }
    
        res.status(200).json({ message: 'Movie found successfully', movie: movieDetails });
      } catch (error) {
        console.error('Error fetching movie:', error);
        res.status(500).json({ message: 'An error occurred while fetching the movie', error: error.message });
      }
    });
    
    //create movie
    app.post('/control/createmovie', authMiddleware, async (req, res) =>{
      
      try {
        const { title, description, released_at, duration, genre, language, avg_rating, total_rating } = req.body;
        const username = req.user.username;
    
        const requiredFields = { title, description, released_at, duration, genre, language, avg_rating, total_rating };
        for (let key in requiredFields) {
          if (!requiredFields[key]) {
            return res.status(400).json({ message: `${key.charAt(0).toUpperCase() + key.slice(1)} is required and cannot be empty` });
          }
        }
      
        const movieData = {
          title,
          description,
          released_at,
          duration,
          genre,
          language,
          created_by: username,
          avg_rating,
          total_rating,
          created_at: new Date(),
          updated_at: new Date()
        };
    
        const result = await moviesCollection.insertOne(movieData);
    
        res.status(200).json({ message: 'Movie created successfully' });
      } catch (error) {
        console.error('Error creating movie:', error);
        res.status(500).json({ message: 'An error occurred while creating the movie', error: error.message });
      }
    });
    
    // update movie
    app.patch('/control/updatemovie/:id',authMiddleware,async(req,res)=>{
      try {
        const movieId = req.params.id;
        const username = req.user.username;
        const updates = req.body;
    
        const restrictedFields = ['_id', 'created_by', 'avg_rating', 'total_rating', 'created_at'];
    
        const movie = await moviesCollection.findOne({ _id: new ObjectId(movieId) });
        if (!movie) {
          return res.status(404).json({ message: 'Movie not found' });
        }


        if (movie.created_by !== username) {
          return res.status(403).json({ message: 'You are not authorized to update this movie' });
        }
    
        // Remove restricted fields from updates
        const filteredUpdates = {};
        for (let key in updates) {
          if (!restrictedFields.includes(key)) {
            filteredUpdates[key] = updates[key];
          }
        }
    
        filteredUpdates.updated_at = new Date();

        const result = await moviesCollection.updateOne(
          { _id: new ObjectId(movieId) },
          { $set: filteredUpdates }
        );
    
        if (result.matchedCount === 0) {
          return res.status(404).json({ message: 'Movie not found for updating' });
        }
    
        res.status(200).json({ message: 'Movie updated successfully' });
      } catch (error) {
        console.error('Error updating movie:', error);
        res.status(500).json({ message: 'An error occurred while updating the movie', error: error.message });
      }
    })
    
    // Add or update a rating
    app.post('/control/ratemovie/:movieId', authMiddleware, async (req, res) => {
      try {
        const movieId = req.params.movieId;
        const userId = req.user.sub;
        const { rating } = req.body;

        if (!rating || rating < 1 || rating > 5) {
          return res.status(400).json({ message: 'Rating must be between 1 and 5' });
        }

        const movie = await moviesCollection.findOne({ _id: new ObjectId(movieId) });
        if (!movie) {
          return res.status(404).json({ message: 'Movie not found' });
        }

        // Check if user already rated this movie
        const existingRating = await ratingsCollection.findOne({ user_id: userId, movie_id: movieId });

        if (existingRating) {
          // Update the existing rating
          await ratingsCollection.updateOne(
            { user_id: userId, movie_id: movieId },
            { $set: { rating, updated_at: new Date() } }
          );
        } else {
          // Create a new rating
          await ratingsCollection.insertOne({
            user_id: userId,
            movie_id: movieId,
            rating,
            created_at: new Date(),
            updated_at: new Date(),
          });
        }

        // Recalculate the average rating and total rating for the movie
        const ratings = await ratingsCollection.find({ movie_id: movieId }).toArray();
        const totalRatings = ratings.length;
        const avgRating = ratings.reduce((sum, r) => sum + r.rating, 0) / totalRatings;

        // Update the movie document
        await moviesCollection.updateOne(
          { _id: new ObjectId(movieId) },
          { $set: { avg_rating: avgRating, total_rating: totalRatings } }
        );

        res.status(200).json({ message: 'Rating submitted successfully', avg_rating: avgRating, total_rating: totalRatings });
      } catch (error) {
        console.error('Error submitting rating:', error);
        res.status(500).json({ message: 'An error occurred while submitting the rating', error: error.message });
      }
    });

    // Report a movie
    app.post('/control/reportmovie/:movieId', authMiddleware, async (req, res) => {
      try {
        const movieId = req.params.movieId;
        const { reason } = req.body;
        const username = req.user.username;

        if (!reason) {
          return res.status(400).json({ message: 'Reason are required' });
        }

        // Check if the movie exists
        const movie = await moviesCollection.findOne({ _id: new ObjectId(movieId) });
        if (!movie) {
          return res.status(404).json({ message: 'Movie not found' });
        }

        const reportData = {
          movieId: new ObjectId(movieId),
          reported_by: username,
          reason,
          status: 'pending', // Can be 'pending', 'approved', or 'rejected'
          created_at: new Date(),
        };

        const result = await reportsCollection.insertOne(reportData);
        res.status(201).json({ message: 'Movie reported successfully', report: result });
      } catch (error) {
        console.error('Error reporting movie:', error);
        res.status(500).json({ message: 'An error occurred while reporting the movie', error: error.message });
      }
    });

    // View all reported movies
    app.get('/control/admin/reportedmovies', authMiddleware, async (req, res) => {
      try {
        const { role } = req.user;
        if (role !== 'admin') {
          return res.status(401).json({ message: 'Authentication token is missing' });
        }
        const result = await reportsCollection.find().toArray();
        res.status(200).json({ message: 'Reported movies retrieved successfully', result });
      } catch (error) {
        console.error('Error retrieving reported movies:', error);
        res.status(500).json({ message: 'An error occurred while retrieving reported movies', error: error.message });
      }
    });

    // Reject a movie report
    app.patch('/control/admin/rejectreport/:reportId', authMiddleware, async (req, res) => {
      try {
        const { role } = req.user;
        if (role !== 'admin') {
          return res.status(403).json({ message: 'Access denied: Admins only' });
        }

        const reportId = req.params.reportId;
        const result = await reportsCollection.updateOne(
          { _id: new ObjectId(reportId) },
          { $set: { status: 'rejected', updated_at: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: 'Report not found' });
        }

        res.status(200).json({ message: 'Report rejected successfully' });
      } catch (error) {
        console.error('Error rejecting report:', error);
        res.status(500).json({ message: 'An error occurred while rejecting the report', error: error.message });
      }
    });

    // Approove a movie report
    app.patch('/control/admin/approvereport/:reportId', authMiddleware, async (req, res) => {
      try {
        const { role } = req.user;
        if (role !== 'admin') {
          return res.status(403).json({ message: 'Access denied: Admins only' });
        }

        const reportId = req.params.reportId;
        const result = await reportsCollection.updateOne(
          { _id: new ObjectId(reportId) },
          { $set: { status: 'approved', updated_at: new Date() } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: 'Report not found' });
        }

        res.status(200).json({ message: 'Report approved successfully' });
      } catch (error) {
        console.error('Error approving report:', error);
        res.status(500).json({ message: 'An error occurred while approving the report', error: error.message });
      }
    });


    app.listen(port,()=>{
        console.log(`surver is running on port ${port}`);
    })

    
  

    