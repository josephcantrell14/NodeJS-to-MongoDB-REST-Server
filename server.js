//@TODO sort queries like getJobRange by startTime, endTime, distance from client (stretch)
// Database Variables
var serverAddress = "mongodb://localhost/Guard-v1"; //MongoDB server address
var frontEndAddress = "http://localhost:8100";  //front end address
var cookieTime = 7 * 24 * 3600 * 1000;  //milliseconds until cookie expiry
var saltFactor = 12;    //salt for bcrypt password hashing

// Set up
var mongoose = require('mongoose');                     // mongoose for mongodb
var Schema = mongoose.Schema;
var morgan = require('morgan');             // log requests to the console (express)
var bodyParser = require('body-parser');    // pull information from HTML POST (express)
var methodOverride = require('method-override'); // simulate DELETE and PUT (express)
var cors = require('cors');
var bcrypt = require('bcryptjs');     //encrypt passwords
var express  = require('express');
var session = require('express-session');
var MongoStore = require('connect-mongo')(session);
var cookieParser = require('cookie-parser');
var app = express();

// Mongoose Configuration
mongoose.connect(serverAddress, {
    reconnectTries: Number.MAX_VALUE,
    reconnectInterval: 1000,
    useMongoClient: true
});


//Sessions - Cookie used to decrease server load
app.use(session({
    store: new MongoStore({
        mongooseConnection: mongoose.connection}),
    cookie: {
        maxAge: cookieTime,
        secure: false,
        httpOnly: false
    },
    secret: 'my6MonGods6are6;',
    resave: false,
    saveUninitialized: false,
    ttl: cookieTime,
}));

app.use(morgan('dev'));                                         // log every request to the console
app.use(cookieParser('my6MonGods6are6'));
app.use(bodyParser.urlencoded({'extended':'true'}));            // parse application/x-www-form-urlencoded
app.use(bodyParser.json());                                     // parse application/json
app.use(bodyParser.json({ type: 'application/vnd.api+json' })); // parse application/vnd.api+json as json
app.use(methodOverride());

var originsWhitelist = [
    frontEndAddress      //front-end url
];
var corsOptions = {
    origin: function(origin, callback){
        var isWhitelisted = originsWhitelist.indexOf(origin) !== -1;
        callback(null, isWhitelisted);
    },
    credentials:true
}
app.use(cors(corsOptions));

app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header('Access-Control-Allow-Methods', 'DELETE, PUT');
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// Schemas and Models
var userSchema = new Schema({
    privilege: Number,
    email: String,
    username: String,
    password: String,
    firstName: String,
    lastName: String,
    designation: String,
    phone: String,
    phoneAlt: String,
    address: {
        street: String,
        city: String,
        state: String,
        zip: String,
        country: String
    },
    profile: {
        image: String,
        description: String,
        armament: Number,
        company: String,
    },
    policeExp: {
        years: Number,
        rank: String,
        id: String,
        department: String,
        supervisorName: String,
        supervisorPhone: String
    },
    militaryExp: {
        years: Number,
        rank: String,
        branch: String,
        country: String
    },
    securityExp: {
        years: Number,
        company: String
    },
    supervisor: {
        firstName: String,
        lastName: String,
        email: String,
        phone: String,
        yearsExperience: Number
    },
    jobs: {
        rating: Number,
        completed: Number,
        currentJobs: [String],
        finishedJobs: [String],
        ratings: [Number]
    },
    preferredHours: {
        Sunday: {
            from: Number,
            to: Number
        },
        Monday: {
            from: Number,
            to: Number
        },
        Tuesday: {
            from: Number,
            to: Number
        },
        Wednesday: {
            from: Number,
            to: Number
        },
        Thursday: {
            from: Number,
            to: Number
        },
        Friday: {
            from: Number,
            to: Number
        },
        Saturday: {
            from: Number,
            to: Number
        }
    }
});
//this method ensures the success of asynchronous password hashing
userSchema.pre('save', function(next) {
   var user = this;
   bcrypt.hash(user.password, saltFactor, function(err, hash) {
       if (err) {
           return next(err);
       }
       user.password = hash;
       next();
   })
});
var jobSchema = new Schema({
    vendorId: String,
    title: String,
    clients: {
        required: Number,
        _ids: [String],
    },
    time: {
        startTime: Number,
        endTime: Number,
        creationTime: Number
    },
    address: {
        street: String,
        city: String,
        state: String,
        zip: String,
        country: String,
        latitude: String,
        longitude: String
    },
    description: String,
    status: Number
})
var User = mongoose.model('User', userSchema);
var Job = mongoose.model('Job', jobSchema);


//     Routes
//Users
app.post('/PostUser', function(req, res) {
    var userData = new User(req.body);
    userData.save(function(err, data) {
        if (err) {
            return res.json(data);
        }
        data.password = undefined;
        return res.json(data); //FILTER PASSWORD WITH SELECT SOMEHOW
    });
});

app.post('/Login', function(req, res) {
    console.log(req.session);
    res.set('Access-Control-Allow-Origin', frontEndAddress);
    res.set('Access-Control-Allow-Credentials', 'true');
    User.findOne({email: req.body.email}, function (err, user) {
        if (err) {
            return res.json(err);
        }
        else if (user) {
            if (req.session && req.session.userId) {
                console.log("cookie found" + " ; " + req.session.userId);
                user.password = undefined;
                return res.json(user)
            } else if (bcrypt.compare(req.body.password, user.password)) {
                console.log("password match" + " ; " + req.session.userId);
                req.session.userId = user._id;
                req.session.save();
                user.password = undefined;
                return res.json(user);
            } else {
                return res.json("password mismatch");
            }
        } else {
            return res.json("no user")
        }
    });
});

app.post('/Logout', function(req, res) {
    console.log(req.session);
    res.set('Access-Control-Allow-Origin', frontEndAddress);
    res.set('Access-Control-Allow-Credentials', 'true');
    if (req.session && req.session.userId) {
        //req.session.userId = undefined;
        req.session.destroy(function(err, destroyed) {
            if (err) {
                return res.json(err);
            } else {
                return res.json("true");
            }
        });
    } else {
        console.log("no session");
        return res.json("true");
    }
});

app.post('/GetUser', function(req, res) {
    console.log("getting user");
    User.findOne({_id: req.body._id}, {password: 0}, function(err, user) {
        if (err) {
            return res.json(err);
        } else if (user) {
            user.password = undefined;
            return res.json(user);
        } else {
            return res.json("False");
        }
    })
});

app.post('/UpdateUser', function(req, res) {
    User.findOneAndUpdate(
        {_id : req.body._id},
        {$set: req.body},
        {new: true},
        function (err, user) {
            if (err) {
                return res.json(err);
            } else if (user) {
                user.save(function (err, data) {
                    if (err) {
                        return res.json(data);
                    }
                    user.password = undefined;
                    return res.json(user);
                });
            }
        }
    )
});

app.delete('/DeleteUser/:id', function(req, res) {
    console.log(req.params.id);
    User.remove({
        _id : req.params.id
    }, function(err, user) {
        res.send(err);
    });
});



//Jobs
app.get('/GetAvailableJobs', function(req, res) {
    console.log("fetching jobs");
    // use mongoose to get all jobs in the database
    Job.find({status: 2}, function(err, jobs) {
        // if there is an error retrieving, send the error. nothing after res.send(err) will execute
        if (err) {
            return res.json(err);
        }
        res.json(jobs.sort({"time.startTime": 1})); // return all jobs in JSON format
    });
});

app.post('/GetJobsRange', function(req, res) {
    console.log("fetching jobs");
    Job.find({"time.startTime": {$gte: req.body.startTime}, "time.endTime": {$lte: req.body.endTime}
    }, function(err, jobs) {
        if (err) {
            return res.json(err);
        }
        res.json(jobs.sort({"time.startTime": 1}));
    });
});
//CHANGE!

app.post('/GetJob', function(req, res) {
    console.log("fetching jobs");
    Job.find({_id: req.body._id}, function(err, job) {
        if (err) {
            return res.json(err);
        }
        res.json(job);
    });
});

app.post('/PostJob', function(req, res) {
    console.log("creating job");
    Job.create(req.body, function(err, job) {
        if (err) {
            return res.json(err);
        }
        return res.json(job);
    });
});

app.post('/UpdateJob', function(req, res) {
    console.log("updating job");
    Job.findOneAndUpdate(
        {_id : req.body._id},
        {$set: req.body},
        {new: true},
        function (err, job) {
            if (err) {
                return res.json(err);
            }
            return res.json(job);
        }
    )
});

app.delete('/CancelJob/:id', function(req, res) {
    console.log(req.params.id);
    Job.remove({
        _id : req.params.id
    }, function(err, job) {
        res.send(err);
    });
});




// listen (start app with node server.js) ======================================
app.listen(8080);
console.log("App listening on port 8080");
