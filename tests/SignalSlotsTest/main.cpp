#include "Counter.h"
#include <iostream>

void Countera::setValue(int value)
{
    if (value != m_value) {
        m_value = value;
        emit valueChanged(value);
        std::cout << "value: "<< this->value()<< std::endl;
    }
}

int main(int argc, char *argv[])
{
    Countera a, b;
    QObject::connect(&a, &Countera::valueChanged,
                     &b, &Countera::setValue);

    a.setValue(12);     // a.value() == 12, b.value() == 12
    b.setValue(48);

    return 0;
}
