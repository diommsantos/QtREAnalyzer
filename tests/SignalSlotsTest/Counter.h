#ifndef COUNTER_H
#define COUNTER_H
#include <QObject>

class Countera : public QObject
{
    Q_OBJECT
    Q_PROPERTY(int proper_property MEMBER proper)
    // Note. The Q_OBJECT macro starts a private section.
    // To declare public members, use the 'public:' access modifier.
public:
    Countera() { m_value = 0; }

    int proper;
    int value() const { return m_value; }

public slots:
    void setValue(int value);
    void slotTest(int i, char *string, float d){return;};

signals:
    void valueChanged(int newValue);
    void signalTest(int i, char *string, float d);

private:
    int m_value;
};
#endif // COUNTER_H
