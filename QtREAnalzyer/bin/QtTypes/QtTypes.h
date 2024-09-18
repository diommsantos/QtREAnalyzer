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