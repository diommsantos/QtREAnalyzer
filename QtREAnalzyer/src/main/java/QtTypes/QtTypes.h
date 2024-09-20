struct QArrayData
{
    int ref; //type should be QtPrivate::RefCount
    int size;
    uint alloc; // should be uint alloc : 31; 
    uint capacityReserved; //should be uint capacityReserved : 1;

    void *offset; //type should be qptrdiff
};

typedef QArrayData QByteArrayData;

struct SuperData {
        const QMetaObject *direct;
};

struct QMetaObject{
	
	struct { // private data
	        SuperData superdata;
	        const QByteArrayData *stringdata;
	        const uint *data;
	        //typedef void (*StaticMetacallFunction)(QObject *, QMetaObject::Call, int, void **);
	        void* static_metacall; //type should be StaticMetacallFunction
	        const SuperData *relatedMetaObjects;
	        void *extradata; //reserved for future use
	} d;
};

enum Type {
        UnknownType = 0, Bool = 1, Int = 2, UInt = 3, LongLong = 4, ULongLong = 5,
        Double = 6, Long = 32, Short = 33, Char = 34, ULong = 35, UShort = 36,
        UChar = 37, Float = 38,
        VoidStar = 31,
        QChar = 7, QString = 10, QStringList = 11, QByteArray = 12,
        QBitArray = 13, QDate = 14, QTime = 15, QDateTime = 16, QUrl = 17,
        QLocale = 18, QRect = 19, QRectF = 20, QSize = 21, QSizeF = 22,
        QLine = 23, QLineF = 24, QPoint = 25, QPointF = 26, QRegExp = 27,
        QEasingCurve = 29, QUuid = 30, QVariant = 41, QModelIndex = 42,
        QPersistentModelIndex = 50, QRegularExpression = 44,
        QJsonValue = 45, QJsonObject = 46, QJsonArray = 47, QJsonDocument = 48,
        QByteArrayList = 49, QObjectStar = 39, SChar = 40,
        Void = 43,
        Nullptr = 51,
        QVariantMap = 8, QVariantList = 9, QVariantHash = 28,
        QCborSimpleType = 52, QCborValue = 53, QCborArray = 54, QCborMap = 55,

        // Gui types
        QFont = 64, QPixmap = 65, QBrush = 66, QColor = 67, QPalette = 68,
        QIcon = 69, QImage = 70, QPolygon = 71, QRegion = 72, QBitmap = 73,
        QCursor = 74, QKeySequence = 75, QPen = 76, QTextLength = 77, QTextFormat = 78,
        QMatrix = 79, QTransform = 80, QMatrix4x4 = 81, QVector2D = 82,
        QVector3D = 83, QVector4D = 84, QQuaternion = 85, QPolygonF = 86, QColorSpace = 87,

        // Widget types
        QSizePolicy = 121,
        LastCoreType = QCborMap,
        LastGuiType = QColorSpace,
        User = 1024
    };